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

use std::net;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, TcpListener};
use tcp_connections;
use std::io;
use std::io::Result as IoResult;
use std::error::Error;
use std::sync::mpsc;
use beacon;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::cmp::Ordering;
pub type Bytes = Vec<u8>;

fn array_to_vec(arr: &[u8]) -> Vec<u8> {
    let mut vector = Vec::new();
    for i in arr.iter() {
        vector.push(*i);
    }
    vector
}

/// Enum representing endpoint of supported protocols
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Endpoint {
    /// TCP endpoint
    Tcp(SocketAddr),
}

impl Endpoint {
    /// Returns SocketAddr.
    pub fn get_address(&self) -> SocketAddr {
        match *self {
            Endpoint::Tcp(address) => address,
        }
    }

    /// Returns whether this endpoint should be chosen over `other` when deciding to connect.
    pub fn is_master(&self, other: &Endpoint) -> bool {
        match *self {
            Endpoint::Tcp(my_address) => {
                match *other {
                    Endpoint::Tcp(other_address) => {
                        if my_address.port() == other_address.port() {
                            return my_address.ip() < other_address.ip();
                        } else {
                            return my_address.port() < other_address.port();
                        }
                    }
                }
            }
        }
        return true;
    }
}

impl Encodable for Endpoint {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let address = array_to_vec(&beacon::serialise_address(self.get_address()));
        CborTagEncode::new(5483_000, &address).encode(e)
    }
}

impl Decodable for Endpoint {
    fn decode<D: Decoder>(d: &mut D)->Result<Endpoint, D::Error> {
        try!(d.read_u64());
        let decoded: Vec<u8> = try!(Decodable::decode(d));
        let address: SocketAddr = beacon::parse_address(&decoded).unwrap();

        Ok(Endpoint::Tcp(address))
    }
}

/// Enum representing port of supported protocols
#[derive(Debug, Clone)]
pub enum Port {
    /// TCP port
    Tcp(u16),
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Endpoint) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Endpoint) -> Ordering {
        use Endpoint::Tcp;
        match *self {
            Tcp(ref a1) => match *other {
                Tcp(ref a2) => compare_ip_addrs(a1, a2)
            }
        }
    }
}

//--------------------------------------------------------------------
pub enum Sender {
    Tcp(tcp_connections::TcpWriter<Bytes>),
}

impl Sender {
    pub fn send(&mut self, bytes: &Bytes) -> IoResult<()> {
        match *self {
            Sender::Tcp(ref mut s) => {
                s.send(&bytes).map_err(|_| {
                // FIXME: This can be done better.
                io::Error::new(io::ErrorKind::NotConnected, "can't send")
            })
            },
        }
    }
}

//--------------------------------------------------------------------
pub enum Receiver {
    Tcp(tcp_connections::TcpReader<Bytes>),
}

impl Receiver {
    pub fn receive(&mut self) -> IoResult<Bytes> {
        match *self {
            Receiver::Tcp(ref r) => {
                match r.recv() {
                    Ok(data) => Ok(data),
                    Err(what) => {
                        return Err(io::Error::new(io::ErrorKind::NotConnected, what.description()));
                    },
                }
            }
        }
    }
}

//--------------------------------------------------------------------
pub enum Acceptor {
    // Channel receiver, TCP listener and calculated local TCP endpoint
    Tcp(mpsc::Receiver<(TcpStream, SocketAddr)>, TcpListener, SocketAddr),
}

impl Acceptor {
    pub fn local_endpoint(&self) -> Endpoint {
        match *self {
            Acceptor::Tcp(_, _, local_address) => Endpoint::Tcp(local_address),
        }
    }
}

pub struct Transport {
    pub receiver: Receiver,
    pub sender: Sender,
    pub remote_endpoint: Endpoint,
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
        }
    }
}

pub fn new_acceptor(port: &Port) -> IoResult<Acceptor> {
    match *port {
        Port::Tcp(ref port) => {
            let (receiver, listener) = try!(tcp_connections::listen(*port));
            // If we fail to calculate local address, fall back to listener.local_addr().
            let local_address =
                if let Ok(address) = get_tcp_listener_local_address(&listener) {
                    address
                } else {
                    try!(listener.local_addr())
                };
            // Discard the first connection since this is caused by calling
            // `get_tcp_listener_local_address` above.
            let _ = receiver.recv();
            Ok(Acceptor::Tcp(receiver, listener, local_address))
        }
    }
}

// FIXME: There needs to be a way to break from this blocking command.
// (Though this seems to be impossible with the current Rust TCP API).
pub fn accept(acceptor: &Acceptor) -> IoResult<Transport> {
    match *acceptor {
        Acceptor::Tcp(ref rx_channel, _, _) => {
            let (stream, remote_endpoint) = try!(rx_channel.recv()
                .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e.description())));

            let (i, o) = try!(tcp_connections::upgrade_tcp(stream));

            Ok(Transport{ receiver: Receiver::Tcp(i),
                          sender: Sender::Tcp(o),
                          remote_endpoint: Endpoint::Tcp(remote_endpoint),
                        })
        }
    }
}

// FIXME: This function is deprecated in favor of Receiver::receive
pub fn receive(receiver: &Receiver) -> IoResult<Bytes> {
    match *receiver {
        Receiver::Tcp(ref r) => r.recv().map_err(|e| {
            io::Error::new(io::ErrorKind::NotConnected, e.description())
        })
    }
}

// FIXME: This function is deprecated in favor of Sender::send
pub fn send(sender: &mut Sender, bytes: &Bytes) -> IoResult<()> {
    match *sender {
        Sender::Tcp(ref mut s) => s.send(&bytes).map_err(|_| {
            // FIXME: This can be done better.
            io::Error::new(io::ErrorKind::NotConnected, "can't send")
        })
    }
}

// It would be easiest to just return listener.local_addr() here, but this yields an IP
// of 0.0.0.0, which is not useful for passing to peers on a different machine.  Hence
// we try and connect to the listener to establish its actual IP address.
//
// TODO - This isn't robust: we're not checking that the listener we connect to is
// actually the one we just created - we should maybe send a magic request and response
// to confirm this.
fn get_tcp_listener_local_address(listener: &TcpListener) -> IoResult<SocketAddr> {
    let listener_local_address = try!(listener.local_addr());
    let listener_port = listener_local_address.port();
    let host = try!(net::lookup_addr(&listener_local_address.ip()));
    let host_interface_itr = try!(net::lookup_host(&host));
    let listener_is_v4 = match listener_local_address {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(_) => false,
    };
    for host_interface in host_interface_itr {
        let attempt_address = match host_interface {
            Ok(SocketAddr::V4(address)) => {
                if !listener_is_v4 {
                    continue;
                }
                SocketAddr::V4(SocketAddrV4::new(*address.ip(), listener_port))
            },
            Ok(SocketAddr::V6(address)) => {
                if listener_is_v4 {
                    continue;
                }
                SocketAddr::V6(SocketAddrV6::new(*address.ip(), listener_port,
                                                 address.flowinfo(), address.scope_id()))
            },
            _ => continue,
        };
        match TcpStream::connect(attempt_address) {
            Ok(stream) => {
                match stream.peer_addr() {
                    Ok(peer_address) => return Ok(peer_address),
                    Err(_) => (),
                }
            },
            _ => (),
        };
    }
    Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Failed to get local address"))
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
