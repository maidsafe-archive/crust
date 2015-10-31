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

use std::fmt;
use transport::{Endpoint, Protocol};
use std::net::SocketAddr;
use util::SocketAddrW;

#[derive(PartialOrd, Ord, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Connection {
    transport_protocol: Protocol,
    peer_addr: SocketAddrW,
    local_addr: SocketAddrW,
}

impl Connection {
    pub fn new(proto: Protocol, local_addr: SocketAddr, peer_addr: SocketAddr)
        -> Connection {
        Connection {
            transport_protocol: proto,
            peer_addr: SocketAddrW(peer_addr),
            local_addr: SocketAddrW(local_addr),
        }
    }

    pub fn peer_endpoint(&self) -> Endpoint {
        match self.transport_protocol {
            Protocol::Tcp => Endpoint::Tcp(self.peer_addr.0.clone()),
            Protocol::Utp => Endpoint::Utp(self.peer_addr.0.clone()),
        }
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        formatter.write_str(&format!("Connection({:?} {:?} -> {:?})",
            self.transport_protocol,
            self.local_addr.0,
            self.peer_addr.0))
    }
}

