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

mod message;
mod acceptor;
mod handshake;
mod sender_receiver;

use std::net::UdpSocket;
use tcp_connections;
use utp_connections;
use std::io;
use std::error::Error;
use std::io::Result as IoResult;
use cbor;
use std::fmt::{Formatter, Debug};
use std::fmt;
use connection::Connection;
use endpoint::{Endpoint, Protocol};

pub use self::message::Message;
pub use self::acceptor::Acceptor;
pub use self::handshake::Handshake;
pub use self::sender_receiver::{Sender, Receiver};

pub struct Transport {
    pub receiver: Receiver,
    pub sender: Sender,
    pub connection_id: Connection,
}

impl Debug for Transport {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Transport {:?}", self.connection_id)
    }
}

// FIXME: There needs to be a way to break from this blocking command.
pub fn connect(remote_ep: Endpoint) -> IoResult<Transport> {
    match remote_ep {
        Endpoint::Tcp(ep) => {
            let (i, o) = try!(tcp_connections::connect_tcp(ep).map_err(|e| {
                io::Error::new(io::ErrorKind::NotConnected, e.description())
            }));
            let connection_id = Connection::new(Protocol::Tcp,
                                                try!(i.local_addr()),
                                                try!(i.peer_addr()));

            Ok(Transport {
                receiver: sender_receiver::Receiver::Tcp(cbor::Decoder::from_reader(i)),
                sender: sender_receiver::Sender::Tcp(o),
                connection_id: connection_id,
            })
        }
        Endpoint::Utp(ep) => {
            let (i, o) = try!(utp_connections::connect_utp(ep).map_err(|e| {
                io::Error::new(io::ErrorKind::NotConnected, e.description())
            }));

            let connection_id = Connection::new(Protocol::Utp, i.local_addr(), i.peer_addr());

            Ok(Transport {
                receiver: sender_receiver::Receiver::Utp(cbor::Decoder::from_reader(i)),
                sender: sender_receiver::Sender::Utp(o),
                connection_id: connection_id,
            })
        }
    }
}

pub fn rendezvous_connect(udp_socket: UdpSocket,
                          public_ep: Endpoint /* of B */)
                          -> IoResult<Transport> {
    match public_ep {
        Endpoint::Utp(ep) => {
            let (i, o) = try!(utp_connections::rendezvous_connect_utp(udp_socket, ep)
                                  .map_err(|e| {
                                      io::Error::new(io::ErrorKind::NotConnected, e.description())
                                  }));

            let connection_id = Connection::new(Protocol::Utp, i.local_addr(), i.peer_addr());

            Ok(Transport {
                receiver: sender_receiver::Receiver::Utp(cbor::Decoder::from_reader(i)),
                sender: sender_receiver::Sender::Utp(o),
                connection_id: connection_id,
            })
        }
        _ => {
            Err(io::Error::new(io::ErrorKind::InvalidInput,
                               "TCP rendezvous connect not supported"))
        }
    }
}

// FIXME: There needs to be a way to break from this blocking command.
// (Though this seems to be impossible with the current Rust TCP API).
pub fn accept(acceptor: &Acceptor) -> IoResult<Transport> {
    match *acceptor {
        Acceptor::Tcp(ref listener) => {
            let (stream, _remote_endpoint) = try!(listener.accept()
                .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e.description())));

            let (i, o) = try!(tcp_connections::upgrade_tcp(stream));

            let connection_id = Connection::new(Protocol::Tcp,
                                                try!(i.local_addr()),
                                                try!(i.peer_addr()));

            Ok(Transport {
                receiver: sender_receiver::Receiver::Tcp(cbor::Decoder::from_reader(i)),
                sender: sender_receiver::Sender::Tcp(o),
                connection_id: connection_id,
            })
        }
        Acceptor::Utp(ref listener) => {
            let (stream, _remote_endpoint) = try!(listener.accept()
                .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e.description())));

            let (i, o) = try!(utp_connections::upgrade_utp(stream));

            let connection_id = Connection::new(Protocol::Utp, i.local_addr(), i.peer_addr());

            Ok(Transport {
                receiver: sender_receiver::Receiver::Utp(cbor::Decoder::from_reader(i)),
                sender: sender_receiver::Sender::Utp(o),
                connection_id: connection_id,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use endpoint::Endpoint;
    use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8, e: u16) -> Endpoint {
        Endpoint::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), e)))
    }

    fn v6(a: u16,
          b: u16,
          c: u16,
          d: u16,
          e: u16,
          f: u16,
          g: u16,
          h: u16,
          i: u16,
          j: u32,
          k: u32)
          -> Endpoint {
        Endpoint::Tcp(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(a, b, c, d, e, f, g, h),
                                                       i,
                                                       j,
                                                       k)))
    }

    fn test(smaller: Endpoint, bigger: Endpoint) {
        assert!(smaller < bigger);
        assert!(bigger > smaller);
        assert!(smaller != bigger);
    }

    #[test]
    fn test_cbor() {
        use cbor::{Decoder, Encoder};
        use std::io::Write;
        use std::net::{TcpStream, TcpListener, SocketAddrV4, Ipv4Addr};
        use std::sync::mpsc::channel;
        use std::thread;

        let handshake = Handshake::default();
        let message = Message::UserBlob(vec![1, 2, 3]);

        let mut enc = Encoder::from_memory();
        enc.encode(&vec![&handshake]).unwrap();
        enc.encode(&vec![&message]).unwrap();
        let mut burst = Vec::from(enc.as_bytes());
        let last_byte = burst.pop().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = channel();
        let t = thread::spawn(move || {
            let addr = Ipv4Addr::new(127, 0, 0, 1);
            let _ = tx.send(TcpStream::connect(SocketAddrV4::new(addr, port)).unwrap());
        });
        let socketa = listener.accept().unwrap().0;
        t.join().unwrap();
        let mut socketb = rx.recv().unwrap();

        let _ = socketb.write_all(&burst[..]);
        let mut dec = Decoder::from_reader(socketa);
        let handshake2: Handshake = dec.decode().next().unwrap().unwrap();
        let _ = socketb.write_all(&vec![last_byte][..]);
        let message2: Message = dec.decode().next().unwrap().unwrap();

        assert_eq!(handshake.mapper_port, handshake2.mapper_port);
        match (message, message2) {
            (Message::UserBlob(ref blob), Message::UserBlob(ref blob2)) => {
                assert_eq!(blob, blob2);
            }
            _ => panic!(""),
        }
    }

    #[test]
    fn test_ord() {
        test(v4(1, 2, 3, 4, 5), v4(2, 2, 3, 4, 5));
        test(v4(1, 2, 3, 4, 5), v4(1, 3, 3, 4, 5));
        test(v4(1, 2, 3, 4, 5), v4(1, 2, 4, 4, 5));
        test(v4(1, 2, 3, 4, 5), v4(1, 2, 3, 5, 5));
        test(v4(1, 2, 3, 4, 5), v4(1, 2, 3, 4, 6));

        test(v4(1, 2, 3, 4, 5), v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
        test(v4(1, 2, 3, 4, 5), v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11));
        test(v4(1, 2, 3, 4, 5), v6(2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12));

        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0));
        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0));
        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0));
        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0));
        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0));
        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0));
        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0));
        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0));
        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0));
        test(v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             v6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1));

        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11));
        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(1, 3, 3, 4, 5, 6, 7, 8, 9, 10, 11));
        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(1, 2, 4, 4, 5, 6, 7, 8, 9, 10, 11));
        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(1, 2, 3, 5, 5, 6, 7, 8, 9, 10, 11));
        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(1, 2, 3, 4, 6, 6, 7, 8, 9, 10, 11));
        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(1, 2, 3, 4, 5, 7, 7, 8, 9, 10, 11));
        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(1, 2, 3, 4, 5, 6, 8, 8, 9, 10, 11));
        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(1, 2, 3, 4, 5, 6, 7, 9, 9, 10, 11));
        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(1, 2, 3, 4, 5, 6, 7, 8, 10, 10, 11));
        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 11));
        test(v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
             v6(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12));
    }
}
