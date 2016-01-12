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

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use ip::IpAddr;

/// Enum representing supported transport protocols
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Protocol {
    /// TCP protocol
    Tcp,
    /// UTP protocol
    Utp,
}

/// Representation of a port (0 - 2^16)
pub type Port = u16;

/// Enum representing endpoint of supported protocols
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, RustcEncodable, RustcDecodable)]
pub struct Endpoint {
    protocol: Protocol,
    socket_addr: SocketAddr,
}

impl Endpoint {
    /// Construct a new Endpoint
    pub fn new(protocol: Protocol, addr: IpAddr, port: Port) -> Endpoint {
        let socketaddr = match addr {
            IpAddr::V4(a) => SocketAddr::V4(SocketAddrV4::new(a, port)),
            IpAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(a, port, 0, 0xe)),
        };
        match protocol {
            Tcp => {
                Endpoint {
                    protocol: Protocol::Tcp,
                    socket_addr: socketaddr,
                }
            }
            Utp => {
                Endpoint {
                    protocol: Protocol::Utp,
                    socket_addr: socketaddr,
                }
            }
        }
    }

    /// Construct a new Endpoint from socketaddr
    pub fn from_socket_addr(protocol: Protocol, addr: SocketAddr) -> Endpoint {
        match protocol {
            Tcp => {
                Endpoint {
                    protocol: protocol,
                    socket_addr: addr,
                }
            }
            Utp => {
                Endpoint {
                    protocol: protocol,
                    socket_addr: addr,
                }
            }
        }
    }

    /// Returns SocketAddr.
    pub fn socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    /// Get protocol
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}
