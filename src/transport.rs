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

use std::net::{SocketAddr, TcpStream, TcpListener, ToSocketAddrs, IpAddr, UdpSocket};
use tcp_connections;
use utp_connections;
use std::cmp::Ordering;
use std::io;
use std::io::Result as IoResult;
use std::error::Error;
use std::sync::mpsc;
use cbor;
use std::str::FromStr;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use utp::UtpListener;
use std::fmt;
use ip;
use connection::Connection;
use std::io::BufReader;
use util;

pub type Bytes = Vec<u8>;

/// Enum representing supported transport protocols
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Protocol {
    /// TCP protocol
    Tcp,
    /// UTP protocol
    Utp,
}

/// Enum representing endpoint of supported protocols
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Endpoint {
    /// TCP endpoint
    Tcp(SocketAddr),
    /// UTP endpoint
    Utp(SocketAddr),
}

impl Endpoint {
    /// Construct a new Endpoint
    pub fn new(addr: IpAddr, port: Port) -> Endpoint {
        match port {
            Port::Tcp(p) => Endpoint::Tcp(SocketAddr::new(addr, p)),
            Port::Utp(p) => Endpoint::Utp(SocketAddr::new(addr, p)),
        }
    }

    /// Creates a Tcp(SocketAddr)
    pub fn tcp<A: ToSocketAddrs>(addr: A) -> Endpoint {
        match addr.to_socket_addrs().unwrap().next() {
            Some(a) => Endpoint::Tcp(a),
            None => panic!("Failed to parse valid IP address"),
        }
    }
    /// Creates a Utp(SocketAddr)
    pub fn utp<A: ToSocketAddrs>(addr: A) -> Endpoint {
        match addr.to_socket_addrs().unwrap().next() {
            Some(a) => Endpoint::Utp(a),
            None => panic!("Failed to parse valid IP address"),
        }
    }
    /// Returns SocketAddr.
    pub fn get_address(&self) -> SocketAddr {
        match *self {
            Endpoint::Tcp(address) => address,
            Endpoint::Utp(address) => address,
        }
    }

    /// Returns port
    pub fn get_port(&self) -> Port {
        match *self {
            Endpoint::Tcp(addr) => Port::Tcp(addr.port()),
            Endpoint::Utp(addr) => Port::Utp(addr.port()),
        }
    }

    /// Convert address format from Port to Endpoint
    pub fn to_ip(&self) -> ip::Endpoint {
        let port = match self.get_port() {
            Port::Tcp(n) => ip::Port::Tcp(n),
            Port::Utp(n) => ip::Port::Udp(n),
        };
        ip::Endpoint::new(self.get_address().ip(), port)
    }

    /// Check whether the current address is specified
    /// returns true if address is un-specified, and false when specified
    pub fn has_unspecified_ip(&self) -> bool {
        match self.get_address().ip() {
            IpAddr::V4(ip) => ip.is_unspecified(),
            IpAddr::V6(ip) => ip.is_unspecified(),
        }
    }

    /// Convert address's format from ::std::net::IpAddr to Endpoint
    pub fn map_ip_addr<F: Fn(IpAddr) -> IpAddr>(&self, f: F) -> Endpoint {
        Endpoint::new(f(self.to_ip().ip()), self.get_port())
    }
}

#[derive(Debug, RustcDecodable, RustcEncodable)]
struct EndpointSerialiser {
    pub protocol : String,
    pub address : String,
}

impl Encodable for Endpoint {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let s = EndpointSerialiser {
            protocol: match *self { Endpoint::Tcp(_) => "tcp".to_string(), Endpoint::Utp(_) => "utp".to_string(), },
            address: self.get_address().to_string()
        };
        try!(s.encode(e));
        Ok(())
    }
}

impl Decodable for Endpoint {
    fn decode<D: Decoder>(d: &mut D)->Result<Endpoint, D::Error> {
        let decoded: EndpointSerialiser = try!(Decodable::decode(d));
        match SocketAddr::from_str(&decoded.address) {
            Ok(address) => if decoded.protocol=="tcp" {
                Ok(Endpoint::Tcp(address))
            } else if decoded.protocol=="utp" {
                Ok(Endpoint::Utp(address))
            } else {
                Err(d.error(&(format!("Unknown Protocol {}", decoded.protocol))))
            },
            _ => Err(d.error(&(format!("Expecting Protocol and SocketAddr string, but found : {:?}", decoded)))),
        }
    }
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Endpoint) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Endpoint) -> Ordering {
        use Endpoint::{Tcp, Utp};
        match *self {
            Tcp(ref a1) => match *other {
                Tcp(ref a2) => util::compare_ip_addrs(a1, a2),
                Utp(_) => Ordering::Greater,
            },
            Utp(ref a1) => match *other {
                Tcp(_) => Ordering::Less,
                Utp(ref a2) => util::compare_ip_addrs(a1, a2)
            },
        }
    }
}

/// Enum representing port of supported protocols
#[derive(Debug, PartialEq, Eq, Hash, Clone, RustcDecodable, RustcEncodable, Copy)]
pub enum Port {
    /// TCP port
    Tcp(u16),
    /// UTP port
    Utp(u16),
}

impl Port {
    /// Return the port
    pub fn number(&self) -> u16 {
        match *self {
            Port::Tcp(p) => p,
            Port::Utp(p) => p,
        }
    }
}

//--------------------------------------------------------------------

#[derive(Debug, Clone, RustcDecodable, RustcEncodable)]
/// After a connection is established, peers should exchange a handshake.
///
/// Only after the handshake is exchanged, crust should generate new connection
/// events.
pub struct Handshake {
    pub mapper_port: Option<u16>,
    pub external_ip: Option<util::SocketAddrV4W>,
}

impl Handshake {
    pub fn default() -> Handshake {
        Handshake {
            mapper_port: None,
            external_ip: None,
        }
    }
}

#[derive(Debug, Clone, RustcDecodable, RustcEncodable)]
pub enum Message {
    /// Arbitrary user blob. This is just an opaque message to Crust.
    UserBlob(Bytes),
    /// We have an external (non-NATed) address+port that other nodes can use as a hole-punching
    /// server.
    HolePunchAddress(util::SocketAddrV4W),
}

//--------------------------------------------------------------------
pub enum Sender {
    Tcp(mpsc::Sender<Vec<u8>>),
    Utp(mpsc::Sender<Vec<u8>>),
}

impl Sender {
    fn send_bytes(&mut self, bytes: Vec<u8>) -> IoResult<()> {
        let sender = match *self {
            Sender::Tcp(ref mut s) => s,
            Sender::Utp(ref mut s) => s,
        };
        sender.send(bytes).map_err(|_| {
            // FIXME: This can be done better.
            io::Error::new(io::ErrorKind::NotConnected, "can't send")
        })
    }

    pub fn send_handshake(&mut self, handshake: Handshake) -> IoResult<()> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&vec![&handshake]).unwrap();
        self.send_bytes(Vec::from(e.as_bytes()))
    }

    pub fn send(&mut self, message: &Message) -> IoResult<()> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&vec![&message]).unwrap();
        self.send_bytes(Vec::from(e.as_bytes()))
    }
}

//--------------------------------------------------------------------
#[allow(variant_size_differences)]
pub enum Receiver {
    Tcp(cbor::Decoder<BufReader<TcpStream>>),
    Utp(cbor::Decoder<BufReader<utp_connections::UtpWrapper>>),
}

impl Receiver {
    fn basic_receive<D: Decodable>(&mut self) -> IoResult<D> {
        match {
            match *self {
                Receiver::Tcp(ref mut decoder) => {
                    decoder.decode::<D>().next()
                },
                Receiver::Utp(ref mut decoder) => {
                    decoder.decode::<D>().next()
                },
            }
        } {
            Some(a) => a.or(Err(io::Error::new(io::ErrorKind::InvalidData,
                                               "Failed to decode CBOR"))),
            None => Err(io::Error::new(io::ErrorKind::NotConnected,
                                       "Decoder reached end of stream")),
        }
    }

    pub fn receive_handshake(&mut self) -> IoResult<Handshake> {
        self.basic_receive()
    }

    pub fn receive(&mut self) -> IoResult<Message> {
        self.basic_receive()
    }
}

//--------------------------------------------------------------------
pub enum Acceptor {
    // TCP listener
    Tcp(TcpListener),
    // UTP listener
    Utp(UtpListener),
}

impl Acceptor {
    pub fn new(port: Port) -> IoResult<Acceptor> {
        match port {
            Port::Tcp(port) => {
                let listener = {
                    if let Ok(listener) = TcpListener::bind(("0.0.0.0", port)) {
                        listener
                    } else {
                        try!(TcpListener::bind(("0.0.0.0", 0)))
                    }
                };

                Ok(Acceptor::Tcp(listener))
            },
            Port::Utp(port) => {
                let listener = try!(UtpListener::bind(("0.0.0.0", port)));
                Ok(Acceptor::Utp(listener))
            },
        }
    }

    pub fn local_port(&self) -> Port {
        self.local_addr().get_port()
    }

    pub fn local_addr(&self) -> Endpoint {
        match *self {
            Acceptor::Tcp(ref listener) => Endpoint::Tcp(listener.local_addr().unwrap()),
            Acceptor::Utp(ref listener) => Endpoint::Utp(listener.local_addr().unwrap()),
        }
    }
}

pub struct Transport {
    pub receiver: Receiver,
    pub sender: Sender,
    pub connection_id: Connection,
}

impl fmt::Debug for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        formatter.write_str(&format!("Transport {:?}", self.connection_id))
    }
}

// FIXME: There needs to be a way to break from this blocking command.
pub fn connect(remote_ep: Endpoint) -> IoResult<Transport> {
    match remote_ep {
        Endpoint::Tcp(ep) => {
            let (i,o) = try!(tcp_connections::connect_tcp(ep)
                             .map_err(|e| io::Error::new(io::ErrorKind::NotConnected,
                                                         e.description())));
            let connection_id = Connection::new(
                Protocol::Tcp,
                try!(i.local_addr()),
                try!(i.peer_addr()),
            );

            Ok(Transport {
                receiver: Receiver::Tcp(cbor::Decoder::from_reader(i)),
                sender: Sender::Tcp(o),
                connection_id: connection_id,
            })
        },
        Endpoint::Utp(ep) => {
            let (i, o) = try!(utp_connections::connect_utp(ep)
                              .map_err(|e| io::Error::new(io::ErrorKind::NotConnected,
                                                          e.description())));

            let connection_id = Connection::new(
                Protocol::Utp,
                i.local_addr(),
                i.peer_addr(),
            );

            Ok(Transport {
                receiver: Receiver::Utp(cbor::Decoder::from_reader(i)),
                sender: Sender::Utp(o),
                connection_id: connection_id,
            })
        }
    }
}

pub fn rendezvous_connect(udp_socket: UdpSocket,
                          public_ep: Endpoint /* of B */ )
                          -> IoResult<Transport> {
    match public_ep {
        Endpoint::Utp(ep) => {
            let (i, o) = try!(utp_connections::rendezvous_connect_utp(udp_socket,
                                                                      ep)
                              .map_err(|e| io::Error::new(io::ErrorKind::NotConnected,
                                                          e.description())));

            let connection_id = Connection::new(
                Protocol::Utp,
                i.local_addr(),
                i.peer_addr(),
            );

            Ok(Transport {
                receiver: Receiver::Utp(cbor::Decoder::from_reader(i)),
                sender: Sender::Utp(o),
                connection_id: connection_id,
            })
        },
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput,
                                "TCP rendezvous connect not supported")),
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

            let connection_id = Connection::new(
                Protocol::Tcp,
                try!(i.local_addr()),
                try!(i.peer_addr())
            );

            Ok(Transport {
                receiver: Receiver::Tcp(cbor::Decoder::from_reader(i)),
                sender: Sender::Tcp(o),
                connection_id: connection_id,
            })
        },
        Acceptor::Utp(ref listener) => {
            let (stream, _remote_endpoint) = try!(listener.accept()
                .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e.description())));

            let (i, o) = try!(utp_connections::upgrade_utp(stream));

            let connection_id = Connection::new(
                Protocol::Utp,
                i.local_addr(),
                i.peer_addr(),
            );

            Ok(Transport{
                receiver: Receiver::Utp(cbor::Decoder::from_reader(i)),
                sender: Sender::Utp(o),
                connection_id: connection_id,
            })
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8, e: u16) -> Endpoint {
        Endpoint::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a,b,c,d),e)))
    }

    fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16, i: u16, j: u32, k: u32) -> Endpoint {
        Endpoint::Tcp(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(a,b,c,d,e,f,g,h),i, j, k)))
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
            let _ = tx.send(TcpStream::connect(SocketAddrV4::new(addr, port))
                            .unwrap());
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
        test(v4(1,2,3,4,5), v4(2,2,3,4,5));
        test(v4(1,2,3,4,5), v4(1,3,3,4,5));
        test(v4(1,2,3,4,5), v4(1,2,4,4,5));
        test(v4(1,2,3,4,5), v4(1,2,3,5,5));
        test(v4(1,2,3,4,5), v4(1,2,3,4,6));

        test(v4(1,2,3,4,5), v6(0,0,0,0,0,0,0,0,0,0,0));
        test(v4(1,2,3,4,5), v6(1,2,3,4,5,6,7,8,9,10,11));
        test(v4(1,2,3,4,5), v6(2,3,4,5,6,7,8,9,10,11,12));

        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(1,0,0,0,0,0,0,0,0,0,0));
        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(0,1,0,0,0,0,0,0,0,0,0));
        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(0,0,1,0,0,0,0,0,0,0,0));
        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(0,0,0,1,0,0,0,0,0,0,0));
        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(0,0,0,0,1,0,0,0,0,0,0));
        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(0,0,0,0,0,1,0,0,0,0,0));
        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(0,0,0,0,0,0,1,0,0,0,0));
        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(0,0,0,0,0,0,0,1,0,0,0));
        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(0,0,0,0,0,0,0,0,1,0,0));
        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(0,0,0,0,0,0,0,0,0,1,0));
        test(v6(0,0,0,0,0,0,0,0,0,0,0), v6(0,0,0,0,0,0,0,0,0,0,1));

        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(2,2,3,4,5,6,7,8,9,10,11));
        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(1,3,3,4,5,6,7,8,9,10,11));
        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(1,2,4,4,5,6,7,8,9,10,11));
        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(1,2,3,5,5,6,7,8,9,10,11));
        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(1,2,3,4,6,6,7,8,9,10,11));
        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(1,2,3,4,5,7,7,8,9,10,11));
        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(1,2,3,4,5,6,8,8,9,10,11));
        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(1,2,3,4,5,6,7,9,9,10,11));
        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(1,2,3,4,5,6,7,8,10,10,11));
        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(1,2,3,4,5,6,7,8,9,11,11));
        test(v6(1,2,3,4,5,6,7,8,9,10,11), v6(1,2,3,4,5,6,7,8,9,10,12));
    }
}
