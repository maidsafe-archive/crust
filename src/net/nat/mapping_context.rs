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


use get_if_addrs::{self, IfAddr};
use net::nat::igd::{self, Gateway};

use util;
use priv_prelude::*;

/// Keeps track of information useful for creating mapped sockets. eg. What networking interfaces
/// does the machine we're running on have? Is there a UPnP router we can talk to? What are some
/// addresses of external STUN servers we can use?
#[derive(Debug)]
pub struct MappingContext {
    our_ifv4s: Vec<Ifv4>,
    our_ifv6s: Vec<Ipv6Addr>,
    peer_stuns: Vec<SocketAddr>,
}

#[derive(Debug, Default)]
pub struct Options {
    pub force_include_port: bool,
}

#[derive(Debug)]
pub struct Ifv4 {
    ip: Ipv4Addr,
    gateway: Option<Gateway>,
    force_include_port: bool,
}

impl MappingContext {
    /// Create a new `MappingContext`
    pub fn new(options: Options) -> BoxFuture<MappingContext, NatError> {
        let Options {
            force_include_port,
        } = options;

        let ifs = match get_if_addrs::get_if_addrs() {
            Ok(ifs) => ifs,
            Err(e) => return future::err(NatError::from(e)).into_boxed(),
        };
        let (mut ifv4s, mut ifv6s) = (Vec::with_capacity(5), Vec::with_capacity(5));
        for interface in ifs {
            match interface.addr {
                IfAddr::V4(v4_addr) => ifv4s.push(v4_addr.ip),
                IfAddr::V6(v6_addr) => ifv6s.push(v6_addr.ip),
            }
        }

        let mut igd_futures = Vec::with_capacity(ifv4s.len());
        for ifv4 in ifv4s {
            if !ifv4.is_loopback() {
                let future = igd::search_gateway_from_timeout(ifv4, Duration::from_secs(1))
                    .then(move |res| {
                        match res {
                            Ok(gateway) => future::ok(Some(gateway)),
                            Err(e) => {
                                info!("Error searching for IGD gateway: {}", e);
                                future::ok(None)
                            },
                        }
                    })
                    .map(move |gateway_opt| {
                        Ifv4 {
                            ip: ifv4,
                            gateway: gateway_opt,
                            force_include_port: force_include_port,
                        }
                    });
                igd_futures.push(future);
            }
        }
        let igd_futures = stream::futures_unordered(igd_futures);
        igd_futures.collect()
            .and_then(|ifv4s| {
                future::ok(MappingContext {
                    our_ifv4s: ifv4s,
                    our_ifv6s: ifv6s,
                    peer_stuns: Vec::with_capacity(10),
                })
            })
            .into_boxed()
    }

    pub fn expand_unspecified_addr(&self, addr: &SocketAddr) -> HashSet<SocketAddr> {
        if !addr.ip().is_unspecified() {
            return hashset!{*addr};
        }

        self.our_ifv4s
        .iter()
        .map(|ifv4| SocketAddr::V4(SocketAddrV4::new(ifv4.ip(), addr.port())))
        .collect::<HashSet<_>>()
    }

    /// Inform the context about external "STUN" servers. Note that crust does not actually use
    /// STUN but a custom STUN-like protocol.
    pub fn add_peer_stuns<A: IntoIterator<Item = SocketAddr>>(&mut self, stun_addrs: A) {
        let listeners = stun_addrs.into_iter().filter(|elt| {
            util::ip_addr_is_global(&elt.ip())
        });
        self.peer_stuns.extend(listeners);
    }

    /// Get v4 interfaces
    pub fn ifv4s(&self) -> &[Ifv4] {
        &self.our_ifv4s
    }

    /// Iterate over the known servers
    pub fn peer_stuns(&self) -> &[SocketAddr] {
        &self.peer_stuns
    }
}

impl Ifv4 {
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    pub fn gateway(&self) -> Option<&Gateway> {
        self.gateway.as_ref()
    }

    pub fn force_include_port(&self) -> bool {
        self.force_include_port
    }
}

#[cfg(test)]
mod tests {
    use tokio_core::reactor::Core;
    use super::*;

    // Run with `cargo test igd -- --ignored` to find if IGD is available for you
    #[test]
    #[ignore]
    fn igd_gateway_available() {
        let mut core = unwrap!(Core::new());
        let res = core.run(MappingContext::new(Options::default())
            .and_then(|mc| {
                assert!(!mc.our_ifv4s.is_empty());

                let mut loopback_found = false;
                let mut non_loopback_found = false;

                for ifv4 in mc.our_ifv4s {
                    if ifv4.ip.is_loopback() {
                        loopback_found = true;
                        assert!(ifv4.gateway.is_none());
                    } else {
                        non_loopback_found = true;
                        assert!(ifv4.gateway.is_some());
                    }
                }

                assert!(loopback_found);
                assert!(non_loopback_found);
                Ok(())
            })
        );
        unwrap!(res);
    }
}

