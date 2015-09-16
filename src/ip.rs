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

use std::net::{SocketAddr, IpAddr};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Port {
    /// TCP port
    Tcp(u16),
    /// UDP port
    Udp(u16),
}

impl Port {
    pub fn number(&self) -> u16 {
        match self {
            &Port::Tcp(n) => n,
            &Port::Udp(n) => n,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Endpoint {
    Tcp(SocketAddr),
    Udp(SocketAddr),
}

impl Endpoint {
    /// Construct a new Endpoint
    pub fn new(addr: IpAddr, port: Port) -> Endpoint {
        match port {
            Port::Tcp(p) => Endpoint::Tcp(SocketAddr::new(addr, p)),
            Port::Udp(p) => Endpoint::Udp(SocketAddr::new(addr, p)),
        }
    }

    pub fn port(&self) -> Port {
        match *self {
            Endpoint::Tcp(saddr) => Port::Tcp(saddr.port()),
            Endpoint::Udp(saddr) => Port::Udp(saddr.port()),
        }
    }

    pub fn ip(&self) -> IpAddr {
        match *self {
            Endpoint::Tcp(saddr) => saddr.ip(),
            Endpoint::Udp(saddr) => saddr.ip(),
        }
    }
}

