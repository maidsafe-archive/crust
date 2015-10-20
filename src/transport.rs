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

use std::net::{SocketAddr, TcpStream, TcpListener, ToSocketAddrs, IpAddr};
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
use utp::UtpSocket;
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

    pub fn to_ip(&self) -> ip::Endpoint {
        let port = match self.get_port() {
            Port::Tcp(n) => ip::Port::Tcp(n),
            Port::Utp(n) => ip::Port::Udp(n),
        };
        ip::Endpoint::new(self.get_address().ip(), port)
    }

    pub fn has_unspecified_ip(&self) -> bool {
        match self.get_address().ip() {
            IpAddr::V4(ip) => ip.is_unspecified(),
            IpAddr::V6(ip) => ip.is_unspecified(),
        }
    }

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
}

impl Handshake {
    pub fn default() -> Handshake {
        Handshake {
            mapper_port: None,
        }
    }
}

#[derive(Debug, Clone, RustcDecodable, RustcEncodable)]
pub enum Message {
    /// Arbitrary user blob. This is just an opaque message to Crust.
    UserBlob(Bytes),
    /// Event to exchange contacts
    Contacts(Vec<Endpoint>),
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
    // Channel receiver, TCP listener
    Tcp(mpsc::Receiver<(TcpStream, SocketAddr)>, TcpListener),
    // Channel receiver, UTP listener and port
    Utp(mpsc::Receiver<(UtpSocket, SocketAddr)>, SocketAddr),
}

impl Acceptor {
    pub fn new(port: Port) -> IoResult<Acceptor> {
        match port {
            Port::Tcp(port) => {
                let (receiver, listener) = try!(tcp_connections::listen(port));
                Ok(Acceptor::Tcp(receiver, listener))
            },
            Port::Utp(port) => {
                let (receiver, listener) = try!(utp_connections::listen(port));
                Ok(Acceptor::Utp(receiver, listener))
            },
        }
    }

    pub fn local_port(&self) -> Port {
        match *self {
            Acceptor::Tcp(_, ref listener) => Port::Tcp(listener.local_addr().unwrap().port()),
            Acceptor::Utp(_, local_addr) => Port::Utp(local_addr.port()),
        }
    }

    pub fn local_addr(&self) -> Endpoint {
        match *self {
            Acceptor::Tcp(_, ref listener) => Endpoint::Tcp(listener.local_addr().unwrap()),
            Acceptor::Utp(_, local_addr) => Endpoint::Utp(local_addr),
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

// FIXME: There needs to be a way to break from this blocking command.
// (Though this seems to be impossible with the current Rust TCP API).
pub fn accept(acceptor: &Acceptor) -> IoResult<Transport> {
    match *acceptor {
        Acceptor::Tcp(ref rx_channel, _) => {
            let rx = rx_channel.recv();
            let (stream, remote_endpoint) = try!(rx
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
        Acceptor::Utp(ref rx_channel, _) => {
            let (stream, remote_endpoint) = try!(rx_channel.recv()
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
