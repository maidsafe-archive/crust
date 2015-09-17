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

use std::net::{TcpListener, TcpStream, SocketAddr, Shutdown};
use std::io::{Error, ErrorKind};
use std::io::Result as IoResult;
use std::thread;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};

/// Connect to a peer and open a send-receive pair.  See `upgrade` for more details.
pub fn connect_tcp(addr: SocketAddr) -> IoResult<(TcpStream, Sender<Vec<u8>>)> {
    let stream = try!(TcpStream::connect(&addr));
    if try!(stream.peer_addr()).port() == try!(stream.local_addr()).port() {
        return Err(Error::new(ErrorKind::ConnectionRefused,
                              "TCP simultaneous open"))
    }

    Ok(try!(upgrade_tcp(stream)))
}

/// Starts listening for connections on this ip and port.
/// Returns:
/// * A receiver of Tcp stream objects.  It is recommended that you `upgrade` these.
/// * A TcpAcceptor.  This can be used to close the listener from outside of the listening thread.
pub fn listen(port: u16) -> IoResult<(Receiver<(TcpStream, SocketAddr)>, TcpListener)> {
    let tcp_listener = {
        /*if let Ok(listener) = TcpListener::bind(("::", port)) {
            listener
        } else if let Ok(listener) = TcpListener::bind(("::", 0)) {
            listener
        } else*/ if let Ok(listener) = TcpListener::bind(("0.0.0.0", port)) {
            listener
        } else {
            try!(TcpListener::bind(("0.0.0.0", 0)))
        }
    };
    let (tx, rx) = mpsc::channel();

    let tcp_listener2 = try!(tcp_listener.try_clone());
    let _ = thread::Builder::new().name("TCP listener".to_string()).spawn(move || {
        loop {
            // if tx.is_closed() {       // FIXME (Prakash)
            //     break;
            // }
            match tcp_listener2.accept() {
                Ok(stream) => {
                    if tx.send(stream).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::TimedOut => {
                    continue;
                }
                Err(_) => {
                    //let _  = tx.error(e);
                    break;
                }
            }
        }
    });
    Ok((rx, tcp_listener))
}

// Almost a straight copy of https://github.com/TyOverby/wire/blob/master/src/tcp.rs
/// Upgrades a TcpStream to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.  If there is an error decoding or encoding
/// values, that respective part is shut down.
pub fn upgrade_tcp(stream: TcpStream)
                   -> IoResult<(TcpStream, Sender<Vec<u8>>)> {
    let s1 = stream;
    let s2 = try!(s1.try_clone());
    Ok((s1, upgrade_writer(s2)))
}

fn upgrade_writer(mut stream: TcpStream) -> Sender<Vec<u8>> {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let _ = thread::spawn(move || {
        while let Ok(v) = rx.recv() {
            use std::io::Write;
            if stream.write_all(&v).is_err() {
                break;
            }
        }
        stream.shutdown(Shutdown::Write)
    });
    tx
}

#[cfg(test)]
mod test {
    use super::*;
    use std::thread;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::Duration;
    use std::io::Read;
    use std::sync::mpsc;

 #[test]
    fn test_small_stream() {
        let (event_receiver, listener) = listen(5483).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (mut i, o) = connect_tcp(SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap()).unwrap();

        for x in 0 .. 10 {
            let x = vec![x];
            o.send(x).unwrap()
        }
        drop(o);
        let _ = thread::spawn(move || {
            for x in event_receiver.iter() {
                let (connection, _) = x;
                // Spawn a new thread for each connection that we get.
                let _ = thread::spawn(move || {
                    let (mut i, o) = upgrade_tcp(connection).unwrap();
                    i.set_read_timeout(Some(Duration::new(5, 0))).unwrap();
                    let mut buf = [0u8; 10];
                    let mut len = 0;
                    while len < 10 {
                        len += i.read(&mut buf[len..]).unwrap();
                    }
                    for i in 0..buf.len() {
                        buf[i] += 1;
                    }
                    o.send(buf.iter().cloned().collect()).unwrap();
                });
            }
        });
        // Collect everything that we get back.
        i.set_read_timeout(Some(Duration::new(5, 0))).unwrap();
        let mut buf = [0u8; 10];
        let mut len = 0;
        while len < 10 {
            len += i.read(&mut buf[len..]).unwrap();
        }
        assert_eq!(buf.iter().cloned().collect::<Vec<_>>(),
                   vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
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

        let (event_receiver, listener) = listen(5483).unwrap();
        let port = listener.local_addr().unwrap().port();

        let (tx, rx) = mpsc::channel();

        for _ in 0..node_count() {
            let tx2 = tx.clone();
            let (mut i, o) = connect_tcp(SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap()).unwrap();
            let _ = thread::spawn(move || {
                let mut buf = Vec::with_capacity(MSG_COUNT);
                for i in 0..MSG_COUNT as u8 {
                    buf.push(i)
                }
                o.send(buf.clone()).unwrap();
                let mut len = 0;
                while len < MSG_COUNT {
                    len += i.read(&mut buf[len..]).unwrap();
                }
                tx2.send(buf)
            });
            let (connection, _) = event_receiver.recv().unwrap();
            let _ = thread::spawn(move || {
                let (mut i, o) = upgrade_tcp(connection).unwrap();
                i.set_read_timeout(Some(Duration::new(5, 0))).unwrap();
                let mut buf = [0u8; MSG_COUNT];
                let mut len = 0;
                while len < MSG_COUNT {
                    len += i.read(&mut buf[len..]).unwrap()
                }
                for i in 0..buf.len() {
                    buf[i] += 1
                }
                o.send(buf.iter().cloned().collect()).unwrap()
            });
        }

        let v = (0..MSG_COUNT as u8).map(|i| i + 1).collect::<Vec<u8>>();
        for _ in 0..node_count() {
            assert_eq!(rx.recv().unwrap(), v);
        }
    }


    // Test to show that the TcpStream has problem reading and writing
    // simultaneously.
    #[ignore]
    #[test]
    fn exchange() {
        use cbor;
        use std::net::{TcpStream, SocketAddr};
        use rustc_serialize::{Decodable, Encodable};
        use cbor::Encoder;

        const MSG_COUNT: u16 = 10;

        fn encode<T>(value: &T) -> Vec<u8> where T: Encodable {
            let mut enc = Encoder::from_memory();
            let _ = enc.encode(&[value]);
            enc.into_bytes()
        }

        let (event_receiver, listener) = listen(0).unwrap();
        let port = listener.local_addr().unwrap().port();

        let addr = SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap();
        let (i1, o1) = connect_tcp(addr).unwrap();
        let (connection, _) = event_receiver.recv().unwrap();
        let (i2, o2) = upgrade_tcp(connection).unwrap();

        fn start_reading(reader: TcpStream) -> thread::JoinHandle<()> {
            thread::spawn(move || {
                let ref r = &reader;
                for i in 0..MSG_COUNT {
                    reader.set_read_timeout(Some(Duration::new(5, 0))).unwrap();
                    let m: String = match cbor::Decoder::from_reader(*r).decode().next() {
                        Some(m) => match m {
                            Ok(m) => m,
                            Err(what) => panic!(format!("Problem decoding message {}", what)),
                        },
                        None => panic!("No more data in TcpStream"),
                    };
                    println!("received {:?}", m);
                }
            })
        }

        let t1 = start_reading(i1);
        let t2 = start_reading(i2);

        let msg = encode(&"MSG".to_string());

        for i in 0..MSG_COUNT {
            assert!(o1.send(msg.clone()).is_ok());
            assert!(o2.send(msg.clone()).is_ok());
        }

        assert!(t1.join().is_ok());
        assert!(t2.join().is_ok());
    }

 // #[test]
    // fn graceful_port_close() {
        //use std::net::{TcpListener};
        //use std::sync::mpsc;
        //use std::thread::spawn;

        //let tcp_listener = TcpListener::bind((("0.0.0.0"), 0)).unwrap();

        //let tcp_listener2 = tcp_listener.try_clone().unwrap();
        //let t = spawn(move || {
        //    loop {
        //        match tcp_listener2.accept() {
        //            Ok(_) => { }
        //            Err(e) => { break; }
        //        }
        //    }
        //});

        //drop(tcp_listener);
        //assert!(t.join().is_ok());
        ////let first_binding;

        ////{
        ////    let (event_receiver, listener) = listen().unwrap();
        ////    first_binding = listener.local_addr().unwrap();
        ////}
        ////{
        ////    let (event_receiver, listener) = listen().unwrap();
        ////    let second_binding = listener.local_addr().unwrap();
        ////    assert_eq!(first_binding.port(), second_binding.port());
        ////}
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
