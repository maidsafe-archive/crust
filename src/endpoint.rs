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

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, TcpListener, ToSocketAddrs,
               UdpSocket};
use ip::IpAddr;
use util::ip_from_socketaddr;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::cmp::Ordering;
use std::str::FromStr;
use util;

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
        let socketaddr = match addr {
            IpAddr::V4(a) => SocketAddr::V4(SocketAddrV4::new(a, port.number())),
            IpAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(a, port.number(), 0, 0xe)),
        };
        match port {
            Port::Tcp(_) => Endpoint::Tcp(socketaddr),
            Port::Utp(_) => Endpoint::Utp(socketaddr),
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
    pub fn get_address(&self) -> IpAddr {
        match *self {
            Endpoint::Tcp(address) => ip_from_socketaddr(address),
            Endpoint::Utp(address) => ip_from_socketaddr(address),
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
    pub fn to_ip(&self) -> Endpoint {
        let port = match self.get_port() {
            Port::Tcp(n) => Port::Tcp(n),
            Port::Utp(n) => Port::Utp(n),
        };
        Endpoint::new(self.get_address(), port)
    }

    /// Check whether the current address is specified
    /// returns true if address is un-specified, and false when specified
    pub fn has_unspecified_ip(&self) -> bool {
        util::is_unspecified(&self.get_address())
    }

    /// Convert address's format from ::std::net::IpAddr to Endpoint
    pub fn map_ip_addr<F: Fn(IpAddr) -> IpAddr>(&self, f: F) -> Endpoint {
        Endpoint::new(f(self.to_ip().get_address()), self.get_port())
    }
}

#[derive(Debug, RustcDecodable, RustcEncodable)]
struct EndpointSerialiser {
    pub protocol: String,
    pub address: String,
}

impl Encodable for Endpoint {
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let s = EndpointSerialiser {
            protocol: match *self {
                Endpoint::Tcp(_) => "tcp".to_owned(),
                Endpoint::Utp(_) => "utp".to_owned(),
            },
            address: self.get_address().to_string(),
        };
        try!(s.encode(e));
        Ok(())
    }
}

impl Decodable for Endpoint {
    fn decode<D: Decoder>(d: &mut D) -> Result<Endpoint, D::Error> {
        let decoded: EndpointSerialiser = try!(Decodable::decode(d));
        match SocketAddr::from_str(&decoded.address) {
            Ok(address) => {
                if decoded.protocol == "tcp" {
                    Ok(Endpoint::Tcp(address))
                } else if decoded.protocol == "utp" {
                    Ok(Endpoint::Utp(address))
                } else {
                    Err(d.error(&(format!("Unknown Protocol {}", decoded.protocol))))
                }
            }
            _ => {
                Err(d.error(&(format!("Expecting Protocol and SocketAddr string, but found : \
                                       {:?}",
                                      decoded))))
            }
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
            Tcp(ref a1) => {
                match *other {
                    Tcp(ref a2) => util::compare_ip_addrs(a1, a2),
                    Utp(_) => Ordering::Greater,
                }
            }
            Utp(ref a1) => {
                match *other {
                    Tcp(_) => Ordering::Less,
                    Utp(ref a2) => util::compare_ip_addrs(a1, a2),
                }
            }
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
