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

//! # `nat_traversal`
//! NAT traversal utilities.

use common::SocketAddr;
use rand;

/// Info exchanged by both parties before performing a rendezvous connection.
#[derive(Debug, Clone, PartialEq, Eq, RustcEncodable, RustcDecodable)]
pub struct PubRendezvousInfo {
    /// A vector of all the mapped addresses that the peer can try connecting to.
    pub endpoints: Vec<SocketAddr>,
    /// Used to identify the peer.
    pub secret: [u8; 4],
}

/// The local half of a `PubRendezvousInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivRendezvousInfo {
    /// Used to identify the peer.
    pub secret: [u8; 4],
}

/// Create a `(PrivRendezvousInfo, PubRendezvousInfo)` pair from a list of
/// mapped socket addresses.
pub fn gen_rendezvous_info(endpoints: Vec<SocketAddr>) -> (PrivRendezvousInfo, PubRendezvousInfo) {
    let secret = rand::random();
    let priv_info = PrivRendezvousInfo { secret: secret };
    let pub_info = PubRendezvousInfo {
        endpoints: endpoints,
        secret: secret,
    };
    (priv_info, pub_info)
}
