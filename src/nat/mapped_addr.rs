// Copyright 2016 MaidSafe.net limited.
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

use std::net::{self, IpAddr};

use common;

/// Socket Address that is publicly accessible if nat_restricted is false.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, RustcEncodable, RustcDecodable)]
pub struct MappedAddr {
    /// Address
    pub addr: common::SocketAddr,
    global: bool,
}

impl MappedAddr {
    /// Constructor
    pub fn new(addr: net::SocketAddr) -> MappedAddr {
        let global = if let IpAddr::V4(addr_v4) = addr.ip() {
            // TODO(Spandan) Currently is_global() is unstable
            !(addr_v4.is_loopback() || addr_v4.is_private() || addr_v4.is_link_local() ||
              addr_v4.is_multicast() || addr_v4.is_broadcast() ||
              addr_v4.is_documentation() || addr_v4.octets() == [0, 0, 0, 0])
        } else {
            false // TODO(Spandan) Rust itself is unstable while dealing with Ipv6 right now
        };

        MappedAddr {
            addr: common::SocketAddr(addr),
            global: global,
        }
    }

    /// Enquire if it's a global address
    pub fn global(&self) -> bool {
        self.global
    }

    /// Get net::SocketAddr
    pub fn addr(&self) -> &net::SocketAddr {
        &self.addr.0
    }
}
