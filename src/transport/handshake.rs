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

use std::str::FromStr;
use std::net;
use socket_addr::{SocketAddrV4, SocketAddr};

/// After a connection is established, peers should exchange a handshake.
///
/// Only after the handshake is exchanged, crust should generate new connection
/// events.
#[derive(Debug, Clone, RustcDecodable, RustcEncodable)]
pub struct Handshake {
    pub mapper_port: Option<u16>,
    pub external_ip: Option<SocketAddr>,
    // used to tell the remote peer their ip (as seen by us)
    pub remote_ip: SocketAddr,
}

impl Default for Handshake {
    fn default() -> Self {
        Handshake {
            mapper_port: None,
            external_ip: None,
            remote_ip: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
        }
    }
}
