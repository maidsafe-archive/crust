// Copyright 2017 MaidSafe.net limited.
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

use igd::{self, PortMappingProtocol};
use log::LogLevel;
use net;

use priv_prelude::*;
use util;
use void;

quick_error! {
    #[derive(Debug)]
    enum MappedTcpSocketError {
        IgdAddAnyPort(e: igd::AddAnyPortError) {
            description("error requesting port mapping from IGD gateway")
            display("error requesting port mapping from IGD gateway: {}", e)
            cause(e)
        }
        Stun(e: StunError, addr: SocketAddr) {
            description("error performing psuedo-stun address discovery with peer")
            display("error performing psuedo-stun address discovery with peer {}. {}", addr, e)
            cause(e)
        }
    }
}

/// Returns a TCP socket and a set of possible external addresses of the socket. For instance, if
/// we're behind a NAT then this will use UPnP and a pseudo-STUN protocol to try and find global IP
/// address+ports that can be used by other peers to connect to this socket.
pub fn mapped_tcp_socket<UID: Uid>(
    handle: &Handle,
    mc: &MappingContext,
    addr: &SocketAddr,
) -> BoxFuture<(TcpBuilder, HashSet<SocketAddr>), io::Error> {
    let try = || -> io::Result<_> {
        let socket = util::new_reusably_bound_tcp_socket(addr)?;
        let addr = socket.local_addr()?;

        let mut mapped_addrs = mc.expand_unspecified_addr(&addr);

        let forced_port = if mc.ifv4s().iter().any(|ifv4| ifv4.force_include_port()) {
            Some(addr.port())
        } else {
            None
        };

        let mut mapping_futures = Vec::new();

        for ifv4 in mc.ifv4s() {
            let gateway = match ifv4.gateway() {
                Some(gateway) => gateway.clone(),
                None => continue,
            };
            let local_endpoint = SocketAddrV4::new(ifv4.ip(), addr.port());
            let future = {
                gateway
                    .get_any_address(PortMappingProtocol::TCP, local_endpoint, 0, "MaidSafeNat")
                    .map(SocketAddr::V4)
                    .map_err(MappedTcpSocketError::IgdAddAnyPort)
                    .into_boxed()
            };
            mapping_futures.push(future);
        }

        for peer_stun in mc.peer_stuns().into_iter().cloned() {
            let future = {
                net::peer::stun::<UID>(handle, &addr, &peer_stun)
                    .map_err(move |e| MappedTcpSocketError::Stun(e, peer_stun))
                    .into_boxed()
            };
            mapping_futures.push(future);
        }

        let timeout = Timeout::new(Duration::from_secs(3), handle)?;
        let mapping_futures = stream::futures_unordered(mapping_futures);
        Ok({
            mapping_futures
                .log_errors(LogLevel::Info, "mapping tcp socket")
                .until(timeout)
                .map_err(|v| void::unreachable(v))
                .collect()
                .and_then(move |addrs| {
                    if let Some(port) = forced_port {
                        mapped_addrs.extend({
                            addrs
                                .iter()
                                .filter(|addr| util::ip_addr_is_global(&addr.ip()))
                                .map(|addr| SocketAddr::new(addr.ip(), port))
                        })
                    }
                    mapped_addrs.extend(addrs);
                    Ok((socket, mapped_addrs))
                })
        })
    };
    future::result(try()).flatten().into_boxed()
}

#[cfg(test)]
mod test {
    use super::*;
    use net::nat::mapping_context;

    use tokio_core::reactor::Core;
    use util::UniqueId;

    #[test]
    fn test_mapped_tcp_socket() {
        let mut core = unwrap!(Core::new());
        let handle = core.handle();
        let res = core.run({
            MappingContext::new(mapping_context::Options::default()).and_then(move |mc| {
                let n = mc.ifv4s().len();

                mapped_tcp_socket::<UniqueId>(&handle, &mc, &addr!("0.0.0.0:0"))
                    .map_err(|e| panic!(e))
                    .map(move |(_socket, addrs)| assert!(addrs.len() >= n))
            })
        });
        unwrap!(res);
    }
}
