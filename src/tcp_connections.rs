// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use sender_receiver::CrustMsg;
use std::net::{TcpStream, Shutdown};
use socket_addr::SocketAddr;
use std::collections::VecDeque;
use std::io;
use std::thread;
use std::sync::mpsc::{self, TryRecvError, Sender};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use event::WriteEvent;

/// Threshold in bytes below which messages are prioritised.
const SIZE_THRESHOLD: usize = 10 * 1024;

/// Connect to a peer and open a send-receive pair.  See `upgrade` for more details.
pub fn connect_tcp(addr: SocketAddr,
                   last_read_instant: Arc<Mutex<Instant>>,
                   heart_beat_timeout: Duration,
                   inactivity_timeout: Duration)
                   -> io::Result<(TcpStream, Sender<WriteEvent>)> {
    let stream = try!(TcpStream::connect(&*addr));
    if try!(stream.peer_addr()).port() == try!(stream.local_addr()).port() {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "TCP simultaneous open"));
    }

    Ok(try!(upgrade_tcp(stream,
                        last_read_instant,
                        heart_beat_timeout,
                        inactivity_timeout)))
}

// Almost a straight copy of https://github.com/TyOverby/wire/blob/master/src/tcp.rs
/// Upgrades a TcpStream to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.
pub fn upgrade_tcp(stream: TcpStream,
                   last_read_instant: Arc<Mutex<Instant>>,
                   heart_beat_timeout: Duration,
                   inactivity_timeout: Duration)
                   -> io::Result<(TcpStream, Sender<WriteEvent>)> {
    use net2::TcpStreamExt;

    if let Err(e) = stream.set_nodelay(true) {
        warn!("Unable to set no delay on tcp stream: {:?}", e);
    }
    let s1 = stream;
    let s2 = try!(s1.try_clone());
    Ok((s1,
        upgrade_writer(s2,
                       last_read_instant,
                       heart_beat_timeout,
                       inactivity_timeout)))
}

fn get_msg_priority(msg: &CrustMsg) -> usize {
    match *msg {
        CrustMsg::Message(ref data) if data.len() > SIZE_THRESHOLD => 1,
        _ => 0,
    }
}

fn upgrade_writer(mut stream: TcpStream,
                  last_read_instant: Arc<Mutex<Instant>>,
                  heart_beat_timeout: Duration,
                  inactivity_timeout: Duration)
                  -> Sender<WriteEvent> {
    use std::io::Write;
    use bincode::SizeLimit;
    use byteorder::{WriteBytesExt, LittleEndian};
    use maidsafe_utilities::serialisation::serialise_with_limit;

    let (tx, rx) = mpsc::channel();
    let send_msgs = move || {
        // Message queues, sorted by descending priority.
        let mut msgs = [VecDeque::new(), VecDeque::new()];
        let mut last_write_instant = Instant::now();

        let heart_beat_payload = unwrap_result!(serialise_with_limit(&CrustMsg::Heartbeat,
                                                                     SizeLimit::Infinite));
        let size = heart_beat_payload.len() as u32;
        let mut heart_beat_size_bytes = Vec::with_capacity(4);
        unwrap_result!(heart_beat_size_bytes.write_u32::<LittleEndian>(size));

        'outer: loop {
            // Sort all messages from the channel by priority.
            loop {
                if Instant::now() > *unwrap_result!(last_read_instant.lock()) + inactivity_timeout {
                    error!("Heartbeat time out - Dropping connection");
                    break 'outer;
                }
                match rx.try_recv() {
                    Ok(WriteEvent::Write(data)) => {
                        let index = get_msg_priority(&data);
                        msgs[index].push_back(data);
                        if msgs[index].len() % 50 == 0 {
                            debug!("{} messages with priority {}.", msgs[index].len(), index);
                        }
                    }
                    Err(TryRecvError::Disconnected) |
                    Ok(WriteEvent::Shutdown) => break 'outer,
                    Err(TryRecvError::Empty) => break,
                }
            }
            // Send the highest-priority message.
            match msgs.iter_mut().filter_map(VecDeque::pop_front).next() {
                Some(data) => {
                    let payload = unwrap_result!(serialise_with_limit(&data, SizeLimit::Infinite));
                    let size = payload.len() as u32;
                    let mut little_endian_size_bytes = Vec::with_capacity(4);
                    unwrap_result!(little_endian_size_bytes.write_u32::<LittleEndian>(size));

                    if let Err(e) = stream.write_all(&little_endian_size_bytes) {
                        debug!("TCP - Failed writing payload size: {:?}", e);
                        break;
                    }
                    if let Err(e) = stream.write_all(&payload) {
                        debug!("TCP - Failed writing payload: {:?}", e);
                        break;
                    }

                    last_write_instant = Instant::now();
                }
                None => {
                    if Instant::now() > last_write_instant + heart_beat_timeout {
                        if let Err(e) = stream.write_all(&heart_beat_size_bytes) {
                            error!("Error writing heartbeat size: {:?}", e);
                            break;
                        }
                        if let Err(e) = stream.write_all(&heart_beat_payload) {
                            error!("Error writing heartbeat payload: {:?}", e);
                            break;
                        }

                        last_write_instant = Instant::now();
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        stream.shutdown(Shutdown::Both)
    };
    let _ = thread!("TCP writer", send_msgs);
    tx
}

#[cfg(test)]
mod test {
    use super::*;
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use std::thread;
    use std::net;
    use std::net::TcpListener;
    use std::str::FromStr;
    use std::time::Duration;
    use std::sync::mpsc;
    use socket_addr::SocketAddr;
    use event::WriteEvent;
    use sender_receiver::CrustMsg;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr(net::SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap())
    }

    #[test]
    fn test_small_stream() {
        use sender_receiver::Receiver;

        let listener = unwrap_result!(TcpListener::bind(("0.0.0.0", 0)));
        let port = unwrap_result!(listener.local_addr()).port();
        let (i, o) = unwrap_result!(connect_tcp(loopback(port)));

        for x in 0..10 {
            let x = vec![x];
            o.send(WriteEvent::Write(CrustMsg::Message(x))).unwrap()
        }
        let t = thread::spawn(move || {
            let connection = unwrap_result!(listener.accept()).0;
            let (i, o) = unwrap_result!(upgrade_tcp(connection));
            unwrap_result!(i.set_read_timeout(Some(Duration::new(5, 0))));
            let mut buf = Vec::new();
            let mut rx = Receiver::tcp(i);
            for _msgnum in 0..10 {
                let msg = match unwrap_result!(rx.receive()) {
                    CrustMsg::Message(msg) => msg,
                    m => panic!("Unexpected crust message: {:#?}", m),
                };
                buf.extend(msg);
            }

            for item in &mut buf {
                *item += 1;
            }
            unwrap_result!(o.send(WriteEvent::Write(CrustMsg::Message(buf))));
        });
        // Collect everything that we get back.
        unwrap_result!(i.set_read_timeout(Some(Duration::new(5, 0))));
        let mut rx = Receiver::tcp(i);
        let msg = match unwrap_result!(rx.receive()) {
            CrustMsg::Message(msg) => msg,
            m => panic!("Unexpected crust message: {:#?}", m),
        };

        assert_eq!(msg, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        drop(o);
        unwrap_result!(t.join());
    }

    // Downscaling node count only for mac for test to pass.
    // FIXME This needs to be removed once too many file descriptor issue is resolved
    fn node_count() -> usize {
        if cfg!(target_os = "macos") {
            64
        } else {
            101
        }
    }

    #[test]
    fn test_multiple_nodes_small_stream() {
        use sender_receiver::Receiver;

        const MSG_COUNT: usize = 5;

        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let (tx, rx) = mpsc::channel();

        for _ in 0..node_count() {
            let tx2 = tx.clone();
            let (i, o) = connect_tcp(loopback(port)).unwrap();
            let send_thread = thread::spawn(move || {
                let mut buf = Vec::with_capacity(MSG_COUNT);
                for i in 0..MSG_COUNT as u8 {
                    buf.push(i)
                }
                o.send(WriteEvent::Write(CrustMsg::Message(buf.clone()))).unwrap();

                let mut rx = Receiver::tcp(i);
                let msg = match unwrap_result!(rx.receive()) {
                    CrustMsg::Message(msg) => msg,
                    m => panic!("Unexpected message {:#?}", m),
                };
                unwrap_result!(tx2.send(msg));
            });
            let (connection, _) = listener.accept().unwrap();
            let echo_thread = thread::spawn(move || {
                let (i, o) = upgrade_tcp(connection).unwrap();
                i.set_read_timeout(Some(Duration::new(5, 0))).unwrap();

                let mut rx = Receiver::tcp(i);
                let mut msg = match unwrap_result!(rx.receive()) {
                    CrustMsg::Message(msg) => msg,
                    m => panic!("Unexpected message {:#?}", m),
                };

                for item in &mut msg {
                    *item += 1
                }
                unwrap_result!(o.send(WriteEvent::Write(CrustMsg::Message(msg))));
            });
            unwrap_result!(send_thread.join());
            unwrap_result!(echo_thread.join());
        }

        let v = (0..MSG_COUNT as u8).map(|i| i + 1).collect::<Vec<u8>>();
        for _ in 0..node_count() {
            let rxd = unwrap_result!(rx.recv());
            assert_eq!(rxd, v);
        }
    }

    #[test]
    fn send_messages_fast() {
        use std::net::TcpStream;
        use sender_receiver::Receiver;

        const MSG_COUNT: u16 = 20;

        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let (_i1, o1) = connect_tcp(loopback(port)).unwrap();
        let (connection, _) = listener.accept().unwrap();
        let (i2, _o2) = upgrade_tcp(connection).unwrap();

        fn read_messages(reader: TcpStream) {
            reader.set_read_timeout(Some(Duration::new(5, 0))).unwrap();
            let mut rx = Receiver::tcp(reader);

            for i in 0..MSG_COUNT {
                match unwrap_result!(rx.receive()) {
                    CrustMsg::Message(msg) => {
                        let s: String = unwrap_result!(deserialise(&msg));
                        assert_eq!(s, format!("MSG{}", i));
                    }
                    m => panic!("Unexpected crust message type {:#?}", m),
                }
            }
        }

        let t = thread::spawn(move || read_messages(i2));

        for i in 0..MSG_COUNT {
            let msg = unwrap_result!(serialise(&format!("MSG{}", i)));
            assert!(o1.send(WriteEvent::Write(CrustMsg::Message(msg.clone()))).is_ok());
        }

        assert!(t.join().is_ok());
    }

    #[test]
    #[ignore]
    fn big_data_exchange() {
        use rand::Rng;
        use std::str::FromStr;
        use sender_receiver::Receiver;
        use std::time::Instant;
        use sodiumoxide::crypto::box_;
        use sodiumoxide::crypto::sign;

        let (pk, sk) = sign::gen_keypair();

        let (en_pk, en_sk) = box_::gen_keypair();
        let en_pk_clone = en_pk.clone();
        let en_sk_clone = en_sk.clone();

        let en_nonce = box_::gen_nonce();
        let en_nonce_clone = en_nonce.clone();

        let mut os_rng = unwrap_result!(::rand::OsRng::new());
        let payload: Vec<u8> = (0..1024 * 1024 * 1).map(|_| os_rng.gen()).collect();
        // let payload = vec![255u8; 1];

        let (finished_tx, finished_rx) = mpsc::channel();

        let _ = thread!("Client", move || {
            let listener = unwrap_result!(TcpListener::bind("127.0.0.1:55559"));
            let (server_strm, _peer_addr) = unwrap_result!(listener.accept());
            let (strm, _writer) = unwrap_result!(upgrade_tcp(server_strm));

            let mut tcp_rx = Receiver::tcp(strm);

            for _ in 0..100 {
                match unwrap_result!(tcp_rx.receive()) {
                    CrustMsg::Message(msg) => {
                        let cipher_text = unwrap_result!(sign::verify(&msg, &pk));
                        let _ = unwrap_result!(box_::open(&cipher_text,
                                                          &en_nonce_clone,
                                                          &en_pk_clone,
                                                          &en_sk_clone));
                    }
                    _ => unreachable!(),
                }
            }

            let _ = finished_tx.send(());
        });

        thread::sleep(Duration::from_millis(100));

        let now = Instant::now();

        let (_stream, writer) =
            unwrap_result!(connect_tcp(SocketAddr(unwrap_result!(FromStr::from_str("127.0.0.1\
                                                                                    :55559")))));

        for _ in 0..100 {
            let cipher_text = box_::seal(&payload, &en_nonce, &en_pk, &en_sk);
            let signed_payload = sign::sign(&cipher_text, &sk);
            unwrap_result!(writer.send(WriteEvent::Write(CrustMsg::Message(signed_payload))));
        }

        unwrap_result!(finished_rx.recv());

        let duration = now.elapsed();

        println!("Duration = {}.{}",
                 duration.as_secs(),
                 duration.subsec_nanos());
    }

}
