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

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crossbeam;
use igd::{self, Gateway};
use get_if_addrs::{self, IfAddr};
use super::NatError;

/// Keeps track of information about external mapping servers
#[derive(Debug, Clone)]
pub struct MappingContext {
    our_ifv4s: Vec<(Ipv4Addr, Option<Gateway>)>,
    our_ifv6s: Vec<Ipv6Addr>,
    tcp_mapping_servers: Vec<SocketAddr>,
}

impl MappingContext {
    /// Create a new `MappingContext`
    pub fn new() -> Result<MappingContext, NatError> {
        let ifs = try!(get_if_addrs::get_if_addrs());
        let (mut ifv4s, mut ifv6s) = (Vec::with_capacity(5), Vec::with_capacity(5));
        for interface in ifs {
            match interface.addr {
                IfAddr::V4(v4_addr) => ifv4s.push((v4_addr.ip, None)),
                IfAddr::V6(v6_addr) => ifv6s.push(v6_addr.ip),
            }
        }

        crossbeam::scope(|scope| {
            let mut guards = Vec::with_capacity(ifv4s.len());
            for ifv4 in &mut ifv4s {
                if !ifv4.0.is_loopback() {
                    guards.push(scope.spawn(move || {
                        ifv4.1 = igd::search_gateway_from_timeout(ifv4.0, Duration::from_secs(1))
                            .ok();
                    }));
                }
            }
        });

        Ok(MappingContext {
            our_ifv4s: ifv4s,
            our_ifv6s: ifv6s,
            tcp_mapping_servers: Vec::with_capacity(10),
        })
    }

    /// Inform the context about external servers
    pub fn add_tcp_mapping_servers<S>(&mut self, servers: S)
        where S: IntoIterator<Item = SocketAddr>
    {
        self.tcp_mapping_servers.extend(servers)
    }

    /// Iterate over the known servers
    pub fn tcp_mapping_servers(&self) -> &Vec<SocketAddr> {
        &self.tcp_mapping_servers
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Run with `cargo test igd -- --ignored` to find if IGD is available for you
    #[test]
    #[ignore]
    fn igd_gateway_available() {
        let mc = MappingContext::new().expect("Could not instantiate MC");
        assert!(!mc.our_ifv4s.is_empty());

        let mut loopback_found = false;
        let mut non_loopback_found = false;

        for ifv4 in mc.our_ifv4s {
            if ifv4.0.is_loopback() {
                loopback_found = true;
                assert!(ifv4.1.is_none());
            } else {
                non_loopback_found = true;
                assert!(ifv4.1.is_some());
            }
        }

        assert!(loopback_found);
        assert!(non_loopback_found);
    }
}
