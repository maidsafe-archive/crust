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

use socket_addr::SocketAddr;

/// This struct contains information needed to Bootstrap and for echo-server services
#[derive(RustcEncodable, RustcDecodable, Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct StaticContactInfo {
    /// This will contain both local and global addresses. Local addresses will be useful on LAN
    /// when someone wants to bootstrap off us and we haven't yet obtained our global address. In
    /// that case the list will contain only the local addresses that the process calling
    /// seek_peers() will get and use.
    pub tcp_acceptors: Vec<SocketAddr>,
    /// TCP mapper server addresses
    pub tcp_mapper_servers: Vec<SocketAddr>,
}
