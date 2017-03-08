// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! Defines the `MappingContext` type


use super::NatError;
use common::get_if_addrs::{self, IfAddr};
use crossbeam;
use igd::{self, Gateway};
use nat;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Keeps track of information about external mapping servers
#[derive(Debug, Clone)]
pub struct MappingContext {
    our_ifv4s: Vec<(Ipv4Addr, Option<Gateway>)>,
    our_ifv6s: Vec<Ipv6Addr>,
    peer_stuns: Vec<SocketAddr>,
}

impl MappingContext {
    /// Create a new `MappingContext`
    pub fn new() -> Result<MappingContext, NatError> {
        let ifs = get_if_addrs::get_if_addrs()?;
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
               peer_stuns: Vec::with_capacity(10),
           })
    }

    /// Inform the context about external "STUN" servers. Note that crust does not actually use
    /// STUN but a custom STUN-like protocol.
    pub fn add_peer_stuns<A: IntoIterator<Item = SocketAddr>>(&mut self, stun_addrs: A) {
        let listeners = stun_addrs.into_iter().filter(|elt| nat::ip_addr_is_global(&elt.ip()));
        self.peer_stuns.extend(listeners);
    }

    /// Get v4 interfaces
    pub fn ifv4s(&self) -> &Vec<(Ipv4Addr, Option<Gateway>)> {
        &self.our_ifv4s
    }

    /// Iterate over the known servers
    pub fn peer_stuns(&self) -> &Vec<SocketAddr> {
        &self.peer_stuns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Run with `cargo test igd -- --ignored` to find if IGD is available for you
    #[test]
    #[ignore]
    fn igd_gateway_available() {
        let mc = unwrap!(MappingContext::new(), "Could not instantiate MC");
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
