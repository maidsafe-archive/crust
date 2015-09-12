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

use std::net::{SocketAddr, TcpStream, TcpListener, ToSocketAddrs};
use tcp_connections;
use utp_connections;
use std::io;
use std::io::Result as IoResult;
use std::error::Error;
use std::sync::mpsc;
use cbor;
use std::str::FromStr;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::cmp::Ordering;
use utp::UtpSocket;
use std::net::IpAddr;
use std::fmt;
pub type Bytes = Vec<u8>;

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
    pub fn get_port(&self) -> u16 {
        match *self {
            Port::Tcp(p) => p,
            Port::Utp(p) => p,
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
                Tcp(ref a2) => compare_ip_addrs(a1, a2),
                Utp(_) => panic!("Should never happen"),
            },
            Utp(ref a1) => match *other {
                Tcp(_) => panic!("Should never happen"),
                Utp(ref a2) => compare_ip_addrs(a1, a2)
            },
        }
    }
}

//--------------------------------------------------------------------

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
    pub fn send(&mut self, message: &Message) -> IoResult<()> {
        let sender = match *self {
            Sender::Tcp(ref mut s) => s,
            Sender::Utp(ref mut s) => s,
        };
        let mut e = cbor::Encoder::from_memory();
        e.encode(&vec![&message]).unwrap();
        sender.send(Vec::from(e.as_bytes())).map_err(|_| {
            // FIXME: This can be done better.
            io::Error::new(io::ErrorKind::NotConnected, "can't send")
        })
    }
}

//--------------------------------------------------------------------
#[allow(variant_size_differences)]
pub enum Receiver {
    Tcp(TcpStream),
    Utp(utp_connections::UtpWrapper),
}

impl Receiver {
    pub fn receive(&mut self) -> IoResult<Message> {
        match {
            match *self {
                Receiver::Tcp(ref mut r) => {
                    cbor::Decoder::from_reader(r).decode().next()
                },
                Receiver::Utp(ref mut r) => {
                    cbor::Decoder::from_reader(r).decode().next()
                },
            }
        } {
            Some(a) => a.or(Err(io::Error::new(io::ErrorKind::InvalidData,
                                               "Failed to decode CBOR"))),
            None => Err(io::Error::new(io::ErrorKind::NotConnected,
                                       "Decoder reached end of stream")),
        }
    }
}

//--------------------------------------------------------------------
pub enum Acceptor {
    // Channel receiver, TCP listener
    Tcp(mpsc::Receiver<(TcpStream, SocketAddr)>, TcpListener),
    // Channel receiver, UTP listener and port
    Utp(mpsc::Receiver<(UtpSocket, SocketAddr)>, u16),
}

impl Acceptor {
    pub fn local_port(&self) -> Port {
        match *self {
            Acceptor::Tcp(_, ref listener) => Port::Tcp(listener.local_addr().unwrap().port()),
            Acceptor::Utp(_, listener) => Port::Utp(listener),
        }
    }
}

pub struct Transport {
    pub receiver: Receiver,
    pub sender: Sender,
    pub remote_endpoint: Endpoint,
}

impl fmt::Debug for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        formatter.write_str(&format!("Transport {:?}", self.remote_endpoint))
    }
}

// FIXME: There needs to be a way to break from this blocking command.
pub fn connect(remote_ep: Endpoint) -> IoResult<Transport> {
    match remote_ep {
        Endpoint::Tcp(ep) => {
            tcp_connections::connect_tcp(ep)
                .map(|(i, o)| {
                    Transport{ receiver: Receiver::Tcp(i),
                                         sender: Sender::Tcp(o),
                                         remote_endpoint: remote_ep,
                             }})
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::NotConnected, e.description())
                })
        },
        Endpoint::Utp(ep) => {
            utp_connections::connect_utp(ep)
                .map(|(i, o)| {
                    Transport{ receiver: Receiver::Utp(i),
                                         sender: Sender::Utp(o),
                                         remote_endpoint: remote_ep,
                             }})
                .map_err(|e| {
                    let _ = warn!("NOTE: Transport connect {} failure due to Utp endpoint {}", ep, e);
                    io::Error::new(io::ErrorKind::NotConnected, e.description())
                })
        }
    }
}

pub fn new_acceptor(port: Port) -> IoResult<Acceptor> {
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

// FIXME: There needs to be a way to break from this blocking command.
// (Though this seems to be impossible with the current Rust TCP API).
pub fn accept(acceptor: &Acceptor) -> IoResult<Transport> {
    match *acceptor {
        Acceptor::Tcp(ref rx_channel, _) => {
            let rx = rx_channel.recv();
            let (stream, remote_endpoint) = try!(rx
                .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e.description())));

            let (i, o) = try!(tcp_connections::upgrade_tcp(stream));

            Ok(Transport{ receiver: Receiver::Tcp(i),
                          sender: Sender::Tcp(o),
                          remote_endpoint: Endpoint::Tcp(remote_endpoint),
                        })
        },
        Acceptor::Utp(ref rx_channel, _) => {
            let (stream, remote_endpoint) = try!(rx_channel.recv()
                .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e.description())));

            let (i, o) = try!(utp_connections::upgrade_utp(stream));

            Ok(Transport{ receiver: Receiver::Utp(i),
                          sender: Sender::Utp(o),
                          remote_endpoint: Endpoint::Utp(remote_endpoint),
                        })
        },
    }
}

fn compare_ip_addrs(a1: &SocketAddr, a2: &SocketAddr) -> Ordering {
    use std::net::SocketAddr::{V4,V6};
    match *a1 {
        V4(ref a1) => match *a2 {
            V4(ref a2) => (a1.ip(), a1.port()).cmp(&(a2.ip(), a2.port())),
            V6(_) => Ordering::Less,
        },
        V6(ref a1) => match *a2 {
            V4(_) => Ordering::Greater,
            V6(ref a2) => (a1.ip(), a1.port(), a1.flowinfo(), a1.scope_id())
                          .cmp(&(a2.ip(), a2.port(), a2.flowinfo(), a2.scope_id())),
        }
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
