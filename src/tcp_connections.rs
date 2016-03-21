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
use std::sync::mpsc::Sender;
use std::time::Duration;
use std::io::{Read, Write};
use net2::{TcpBuilder, TcpStreamExt};
use crossbeam;

use socket_utils::enable_so_reuseport;
use event::WriteEvent;
use listener_message::{ListenerRequest, ListenerResponse};
use maidsafe_utilities::serialisation::{serialise, deserialise};

/// Connect to a peer and open a send-receive pair.  See `upgrade` for more details.
pub fn connect_tcp(addr: SocketAddr) -> io::Result<(TcpStream, Sender<WriteEvent>)> {
    let stream = try!(TcpStream::connect(&*addr));
    if try!(stream.peer_addr()).port() == try!(stream.local_addr()).port() {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "TCP simultaneous open"));
    }

    Ok(try!(upgrade_tcp(stream)))
}

// Almost a straight copy of https://github.com/TyOverby/wire/blob/master/src/tcp.rs
/// Upgrades a TcpStream to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.
pub fn upgrade_tcp(stream: TcpStream) -> io::Result<(TcpStream, Sender<WriteEvent>)> {
    try!(stream.set_keepalive(Some(Duration::from_secs(10))));
    let s1 = stream;
    let s2 = try!(s1.try_clone());
    Ok((s1, upgrade_writer(s2)))
}

fn upgrade_writer(mut stream: TcpStream) -> Sender<WriteEvent> {
    let (tx, rx) = mpsc::channel();
    let _ = unwrap_result!(thread::Builder::new()
                               .name("TCP writer".to_owned())
                               .spawn(move || {
                                   while let Ok(event) = rx.recv() {
                                       match event {
                                           WriteEvent::Write(data) => {
                                               use std::io::Write;
                                               let msg = unwrap_result!(serialise(&data));
                                               if stream.write_all(&msg).is_err() {
                                                   break;
                                               }
                                           }
                                           WriteEvent::Shutdown => break,
                                       }
                                   }
                                   stream.shutdown(Shutdown::Both)
                               }));
    tx
}

/// Returns the stream along with the peer's SocketAddr
pub fn blocking_tcp_punch_hole(local_addr: SocketAddr,
                               // secret: Option<[u8; 4]>,
                               peer_addrs: Vec<SocketAddr>)
                               -> io::Result<TcpStream> {
    // TODO(canndrew): Use secrets or public keys to make sure we have connected to the peer and
    // not some random endpoint
    crossbeam::scope(|scope| {
        let listen_thread = scope.spawn(|| -> io::Result<_> {
            let socket = try!(TcpBuilder::new_v4());
            let _ = try!(socket.reuse_address(true));
            try!(enable_so_reuseport(&socket));
            let _ = try!(socket.bind(&*local_addr));
            let listener = try!(socket.listen(1));
            let (stream, addr) = try!(listener.accept());
            Ok((stream, addr))
        });
        let mut connect_threads = Vec::new();
        for peer_addr in &peer_addrs {
            let connect_thread = scope.spawn(move || -> io::Result<_> {
                let connector = try!(TcpBuilder::new_v4());
                let _ = try!(connector.reuse_address(true));
                try!(enable_so_reuseport(&connector));
                let _ = try!(connector.bind(&*local_addr));
                let stream = try!(connector.connect(&**peer_addr));
                Ok(stream)
            });
            connect_threads.push(connect_thread);
        }
        match listen_thread.join() {
            Ok((stream, _)) => Ok(stream),
            Err(_) => {
                for connect_thread in connect_threads {
                    match connect_thread.join() {
                        Ok(stream) => return Ok(stream),
                        Err(_) => continue,
                    }
                }
                Err(io::Error::new(io::ErrorKind::Other, "Tcp rendezvous connect failed"))
            }
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use maidsafe_utilities::serialisation::{deserialise_from, serialise};
    use std::thread;
    use std::net;
    use std::net::TcpListener;
    use std::str::FromStr;
    use std::time::Duration;
    use std::io::Read;
    use std::sync::mpsc;
    use socket_addr::SocketAddr;
    use event::WriteEvent;
    use sender_receiver::CrustMsg;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr(net::SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap())
    }

    #[test]
    fn test_small_stream() {
        let listener = unwrap_result!(TcpListener::bind(("0.0.0.0", 0)));
        let port = unwrap_result!(listener.local_addr()).port();
        let (mut i, o) = unwrap_result!(connect_tcp(loopback(port)));

        for x in 0..10 {
            let x = vec![x];
            o.send(WriteEvent::Write(CrustMsg::Message(x))).unwrap()
        }
        let t = thread::spawn(move || {
            let connection = unwrap_result!(listener.accept()).0;
            let (mut i, o) = unwrap_result!(upgrade_tcp(connection));
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
            unwrap_result!(o.send(WriteEvent::Write(CrustMsg::Message(buf))));
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
            let (mut i, o) = connect_tcp(loopback(port)).unwrap();
            let send_thread = thread::spawn(move || {
                let mut buf = Vec::with_capacity(MSG_COUNT);
                for i in 0..MSG_COUNT as u8 {
                    buf.push(i)
                }
                o.send(WriteEvent::Write(CrustMsg::Message(buf.clone()))).unwrap();

                let msg = match unwrap_result!(deserialise_from::<_, CrustMsg>(&mut i)) {
                    CrustMsg::Message(msg) => msg,
                    m => panic!("Unexpected message {:#?}", m),
                };
                unwrap_result!(tx2.send(msg));
            });
            let (connection, _) = listener.accept().unwrap();
            let echo_thread = thread::spawn(move || {
                let (mut i, o) = upgrade_tcp(connection).unwrap();
                i.set_read_timeout(Some(Duration::new(5, 0))).unwrap();

                let mut msg = match unwrap_result!(deserialise_from::<_, CrustMsg>(&mut i)) {
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
        use rustc_serialize::{Decodable, Encodable};

        const MSG_COUNT: u16 = 20;

        fn encode<T>(value: &T) -> Vec<u8>
            where T: Encodable
        {
            unwrap_result!(serialise(value))
        }

        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let (_i1, o1) = connect_tcp(loopback(port)).unwrap();
        let (connection, _) = listener.accept().unwrap();
        let (i2, _o2) = upgrade_tcp(connection).unwrap();

        fn read_messages(mut reader: TcpStream) {
            reader.set_read_timeout(Some(Duration::new(5, 0))).unwrap();

            for _ in 0..MSG_COUNT {
                match deserialise_from::<_, CrustMsg>(&mut reader) {
                    Ok(CrustMsg::Message(msg)) => (),
                    Ok(m) => panic!("Unexpected crust message type {:#?}", m),
                    Err(what) => panic!("Problem decoding message {}", what),
                }
            }
        }

        let t = thread::spawn(move || read_messages(i2));

        for i in 0..MSG_COUNT {
            let msg = encode(&format!("MSG{}", i));
            assert!(o1.send(WriteEvent::Write(CrustMsg::Message(msg.clone()))).is_ok());
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
