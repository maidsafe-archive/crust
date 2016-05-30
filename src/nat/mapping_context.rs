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

//! Defines the `MappingContext` type

use std::net::SocketAddr;
use std::slice;

/// Keeps track of information about external mapping servers
pub struct MappingContext {
    tcp_mapping_servers: Vec<SocketAddr>,
}

impl MappingContext {
    /// Create a new `MappingContext`
    pub fn new() -> MappingContext {
        MappingContext { tcp_mapping_servers: Vec::new() }
    }

    /// Inform the context about external servers
    pub fn add_tcp_mapping_servers<S>(&mut self, servers: S)
        where S: IntoIterator<Item = SocketAddr>
    {
        self.tcp_mapping_servers.extend(servers)
    }

    /// Iterate over the known servers
    pub fn tcp_mapping_servers(&self) -> IterTcpMappingServers {
        self.tcp_mapping_servers.iter()
    }
}

impl Default for MappingContext {
    fn default() -> MappingContext {
        MappingContext::new()
    }
}

/// Iterator returned by `MappingContext::tcp_mapping_servers`
pub type IterTcpMappingServers<'m> = slice::Iter<'m, SocketAddr>;
