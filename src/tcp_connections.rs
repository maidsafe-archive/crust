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

use std::net::{TcpStream, Shutdown};
use socket_addr::SocketAddr;
use std::io;
use std::thread;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, TryRecvError};
use std::io::Write;
use std::sync::{Arc, Mutex};

use event::WriteEvent;
use maidsafe_utilities::serialisation::serialise;
use std::time::{Duration, Instant};
use sender_receiver::CrustMsg;

/// If a message is larger than this number of bytes, it may be dropped when traffic is high.
const DROP_MSG_SIZE: usize = 8 * 1024;
/// If a large message is that old (in seconds) when it arrives in the sending thread, drop it.
const DROP_MSG_TIMEOUT_SECS: u64 = 10;

/// Connect to a peer and open a send-receive pair.  See `upgrade` for more details.
pub fn connect_tcp(addr: SocketAddr,
                   last_read_activity: Arc<Mutex<Instant>>,
                   heartbeat_timeout: Duration,
                   inactivity_timeout: Duration)
                   -> io::Result<(TcpStream, Sender<WriteEvent>)> {
    let stream = try!(TcpStream::connect(&*addr));
    if try!(stream.peer_addr()).port() == try!(stream.local_addr()).port() {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "TCP simultaneous open"));
    }

    Ok(try!(upgrade_tcp(stream,
                        last_read_activity,
                        heartbeat_timeout,
                        inactivity_timeout)))
}

// Almost a straight copy of https://github.com/TyOverby/wire/blob/master/src/tcp.rs
/// Upgrades a TcpStream to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.
pub fn upgrade_tcp(stream: TcpStream,
                   last_read_activity: Arc<Mutex<Instant>>,
                   heartbeat_timeout: Duration,
                   inactivity_timeout: Duration)
                   -> io::Result<(TcpStream, Sender<WriteEvent>)> {
    let s1 = stream;
    let s2 = try!(s1.try_clone());
    Ok((s1,
        upgrade_writer(s2,
                       last_read_activity,
                       heartbeat_timeout,
                       inactivity_timeout)))
}

fn upgrade_writer(mut stream: TcpStream,
                  last_read_activity: Arc<Mutex<Instant>>,
                  heartbeat_timeout: Duration,
                  inactivity_timeout: Duration)
                  -> Sender<WriteEvent> {
    let (tx, rx) = mpsc::channel();
    let _ = unwrap_result!(thread::Builder::new()
                               .name("TCP writer".to_owned())
                               .spawn(move || {
                                   let heartbeat_msg =
                                       unwrap_result!(serialise(&CrustMsg::Heartbeat));
                                   let mut last_write_activity = Instant::now();
                                   loop {
                                       use std::io::Write;
                                       match rx.try_recv() {
                                           Ok(WriteEvent::Write(data, timestamp)) => {
                                               let msg = unwrap_result!(serialise(&data));
                                               if msg.len() > DROP_MSG_SIZE &&
                                                  timestamp.elapsed().as_secs() >
                                                  DROP_MSG_TIMEOUT_SECS {
                                                   warn!("Upstream bandwidth too low - dropping \
                                                          message with {} bytes.",
                                                         msg.len());
                                                   continue;
                                               }
                                               let start_timestamp = Instant::now();
                                               if stream.write_all(&msg).is_err() {
                                                   break;
                                               }
                                               if msg.len() > DROP_MSG_SIZE {
                                                   trace!("Sent {} bytes in {} seconds.",
                                                          msg.len(),
                                                          start_timestamp.elapsed().as_secs());
                                               }
                                               last_write_activity = Instant::now();
                                           }
                                           Ok(WriteEvent::Shutdown) => break,
                                           Err(TryRecvError::Empty) => {
                                               let now = Instant::now();
                                               let last_read_activity = last_read_activity.lock()
                                                                                          .unwrap()
                                                                                          .clone();
                                               let inactivity_deadline = last_read_activity +
                                                                         inactivity_timeout;
                                               if now > inactivity_deadline {
                                                   info!("Stale connection. Dropping...");
                                                   break;
                                               }
                                               let heartbeat_deadline = last_write_activity +
                                                                        heartbeat_timeout;
                                               if now > heartbeat_deadline {
                                                   if let Err(e) =
                                                          stream.write_all(&heartbeat_msg) {
                                                       error!("Error sending: {:?}", e);
                                                       break;
                                                   }
                                                   last_write_activity = Instant::now();
                                               } else {
                                                   // Avoid CPU throttling
                                                   thread::sleep(Duration::from_millis(10));
                                               }
                                           }
                                           Err(TryRecvError::Disconnected) => break,
                                       }
                                   }
                                   stream.shutdown(Shutdown::Both)
                               }));
    tx
}

#[cfg(test)]
mod test {
    use super::*;
    use maidsafe_utilities::serialisation::{deserialise_from, deserialise, serialise};
    use std::thread;
    use std::net;
    use std::net::TcpListener;
    use std::str::FromStr;
    use std::time::{Duration, Instant};
    use std::sync::mpsc;
    use socket_addr::SocketAddr;
    use event::WriteEvent;
    use sender_receiver::CrustMsg;
    use std::sync::{Arc, Mutex};

    static HEARTBEAT_TIMEOUT_SECS: u64 = 1 * 60;
    static INACTIVITY_TIMEOUT_SECS: u64 = 3 * 60;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr(net::SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap())
    }

    #[test]
    fn test_small_stream() {
        let listener = unwrap_result!(TcpListener::bind(("0.0.0.0", 0)));
        let port = unwrap_result!(listener.local_addr()).port();
        let last_read_activity = Arc::new(Mutex::new(Instant::now()));
        let (mut i, o) = unwrap_result!(connect_tcp(loopback(port),
                                                    last_read_activity,
                                                    Duration::from_secs(HEARTBEAT_TIMEOUT_SECS),
                                                    Duration::from_secs(INACTIVITY_TIMEOUT_SECS)));

        for x in 0..10 {
            let x = vec![x];
            o.send(WriteEvent::Write(CrustMsg::Message(x), Instant::now())).unwrap()
        }
        let t = thread::spawn(move || {
            let connection = unwrap_result!(listener.accept()).0;
            let last_read_activity = Arc::new(Mutex::new(Instant::now()));
            let (mut i, o) = unwrap_result!(upgrade_tcp(connection,
                                           last_read_activity,
                                           Duration::from_secs(HEARTBEAT_TIMEOUT_SECS),
                                           Duration::from_secs(INACTIVITY_TIMEOUT_SECS)));
            unwrap_result!(i.set_read_timeout(Some(Duration::new(5, 0))));
            let mut buf = Vec::new();
            for _msgnum in 0..10 {
                let msg = match unwrap_result!(deserialise_from::<_, CrustMsg>(&mut i)) {
                    CrustMsg::Message(msg) => msg,
                    m => panic!("Unexpected crust message: {:#?}", m),
                };
                buf.extend(msg);
            }

            for item in &mut buf {
                *item += 1;
            }
            unwrap_result!(o.send(WriteEvent::Write(CrustMsg::Message(buf), Instant::now())));
        });
        // Collect everything that we get back.
        unwrap_result!(i.set_read_timeout(Some(Duration::new(5, 0))));
        let msg = match unwrap_result!(deserialise_from::<_, CrustMsg>(&mut i)) {
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
        const MSG_COUNT: usize = 5;

        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let (tx, rx) = mpsc::channel();

        for _ in 0..node_count() {
            let tx2 = tx.clone();
            let last_read_activity = Arc::new(Mutex::new(Instant::now()));
            let (mut i, o) = connect_tcp(loopback(port),
                                         last_read_activity,
                                         Duration::from_secs(HEARTBEAT_TIMEOUT_SECS),
                                         Duration::from_secs(INACTIVITY_TIMEOUT_SECS))
                                 .unwrap();
            let send_thread = thread::spawn(move || {
                let mut buf = Vec::with_capacity(MSG_COUNT);
                for i in 0..MSG_COUNT as u8 {
                    buf.push(i)
                }
                o.send(WriteEvent::Write(CrustMsg::Message(buf.clone()), Instant::now())).unwrap();

                let msg = match unwrap_result!(deserialise_from::<_, CrustMsg>(&mut i)) {
                    CrustMsg::Message(msg) => msg,
                    m => panic!("Unexpected message {:#?}", m),
                };
                unwrap_result!(tx2.send(msg));
            });
            let (connection, _) = listener.accept().unwrap();
            let echo_thread = thread::spawn(move || {
                let last_read_activity = Arc::new(Mutex::new(Instant::now()));
                let (mut i, o) = upgrade_tcp(connection,
                                             last_read_activity,
                                             Duration::from_secs(HEARTBEAT_TIMEOUT_SECS),
                                             Duration::from_secs(INACTIVITY_TIMEOUT_SECS))
                                     .unwrap();
                i.set_read_timeout(Some(Duration::new(5, 0))).unwrap();

                let mut msg = match unwrap_result!(deserialise_from::<_, CrustMsg>(&mut i)) {
                    CrustMsg::Message(msg) => msg,
                    m => panic!("Unexpected message {:#?}", m),
                };

                for item in &mut msg {
                    *item += 1
                }
                unwrap_result!(o.send(WriteEvent::Write(CrustMsg::Message(msg), Instant::now())));
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

        const MSG_COUNT: u16 = 20;

        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let last_read_activity = Arc::new(Mutex::new(Instant::now()));
        let (_i1, o1) = connect_tcp(loopback(port),
                                    last_read_activity,
                                    Duration::from_secs(HEARTBEAT_TIMEOUT_SECS),
                                    Duration::from_secs(INACTIVITY_TIMEOUT_SECS))
                            .unwrap();
        let (connection, _) = listener.accept().unwrap();
        let last_read_activity = Arc::new(Mutex::new(Instant::now()));
        let (i2, _o2) = upgrade_tcp(connection,
                                    last_read_activity,
                                    Duration::from_secs(HEARTBEAT_TIMEOUT_SECS),
                                    Duration::from_secs(INACTIVITY_TIMEOUT_SECS))
                            .unwrap();

        fn read_messages(mut reader: TcpStream) {
            reader.set_read_timeout(Some(Duration::new(5, 0))).unwrap();

            for i in 0..MSG_COUNT {
                match deserialise_from::<_, CrustMsg>(&mut reader) {
                    Ok(CrustMsg::Message(msg)) => {
                        let s: String = unwrap_result!(deserialise(&msg));
                        assert_eq!(s, format!("MSG{}", i));
                    }
                    Ok(m) => panic!("Unexpected crust message type {:#?}", m),
                    Err(what) => panic!("Problem decoding message {}", what),
                }
            }
        }

        let t = thread::spawn(move || read_messages(i2));

        for i in 0..MSG_COUNT {
            let msg = unwrap_result!(serialise(&format!("MSG{}", i)));
            assert!(o1.send(WriteEvent::Write(CrustMsg::Message(msg.clone()), Instant::now()))
                      .is_ok());
        }

        assert!(t.join().is_ok());
    }

    // #[test]
    // fn graceful_port_close() {
    // use std::net::{TcpListener};
    // use std::sync::mpsc;
    // use std::thread::spawn;

    // let tcp_listener = TcpListener::bind((("0.0.0.0"), 0)).unwrap();

    // let tcp_listener2 = tcp_listener.try_clone().unwrap();
    // let t = spawn(move || {
    //    loop {
    //        match tcp_listener2.accept() {
    //            Ok(_) => { }
    //            Err(e) => { break; }
    //        }
    //    }
    // });

    // drop(tcp_listener);
    // assert!(t.join().is_ok());
    // let first_binding;

    // {
    //     let (event_receiver, listener) = listen().unwrap();
    //     first_binding = listener.local_addr().unwrap();
    // }
    // {
    //     let (event_receiver, listener) = listen().unwrap();
    //     let second_binding = listener.local_addr().unwrap();
    //     assert_eq!(first_binding.port(), second_binding.port());
    // }
    // }

    // #[test]
    // fn test_stream_large_data() {
    //     // Has to be sent over several packets
    //     const LEN: usize = 1024 * 1024;
    //     let data: Vec<u8> = (0..LEN).map(|idx| idx as u8).collect();
    //     assert_eq!(LEN, data.len());
    //
    //     let d = data.clone(\;
    //     let receiver_addr = next_test_ip4();
    //     let mut receiver = UtpStream::bind(receiver_addr);
    //
    //     thread::spawn(move || {
    //         let mut sender = iotry!(UtpStream::connect(receiver_addr));
    //         iotry!(sender.write(&d[..]));
    //         iotry!(sender.close());
    //     });
    //
    //     let read = iotry!(receiver.read_to_end());
    //     assert!(!read.is_empty());
    //     assert_eq!(read.len(), data.len());
    //     assert_eq!(read, data);
    // }

}
