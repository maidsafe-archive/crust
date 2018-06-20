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

use futures::{Future, Sink, Stream};
use get_if_addrs::{self, IfAddr};
use maidsafe_utilities::serialisation::SerialisationError;
use net::service_discovery::msg::DiscoveryMsg;
use priv_prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::net::Ipv4Addr;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::Handle;
use util::SerdeUdpCodec;

/// Returns IP address and listener addresses of a first node to respond to service discovery
/// request.
pub fn discover<T>(
    handle: &Handle,
    port: u16,
    our_pk: PublicKey,
    our_sk: SecretKey,
) -> IoFuture<BoxStream<(Ipv4Addr, T), Void>>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    let bind_addr = addr!("0.0.0.0:0");
    let request = DiscoveryMsg::Request(our_pk);
    let anon_decrypt_ctx = CryptoContext::anonymous_decrypt(our_pk, our_sk);

    future::result(UdpSocket::bind(&bind_addr, handle))
        .and_then(|socket| {
            socket.set_broadcast(true)?;
            let framed = socket.framed(SerdeUdpCodec::new());
            Ok(framed)
        })
        .and_then(move |framed| {
            future::result(get_if_addrs::get_if_addrs())
                .map(stream::iter_ok)
                .flatten_stream()
                .filter_map(|iface| match iface.addr {
                    IfAddr::V4(ifv4_addr) => match ifv4_addr.broadcast {
                        Some(broadcast) => Some(broadcast),
                        None => {
                            let ip = u32::from(ifv4_addr.ip);
                            let netmask = u32::from(ifv4_addr.netmask);
                            let broadcast = u32::from(ipv4!("255.255.255.255"));

                            let prefix = ip & netmask;
                            let postfix = broadcast & !netmask;

                            Some(Ipv4Addr::from(prefix | postfix))
                        }
                    },
                    IfAddr::V6(..) => None,
                })
                .fold(framed, move |framed, broadcast_ip| {
                    let broadcast_addr = SocketAddr::V4(SocketAddrV4::new(broadcast_ip, port));
                    framed.send((broadcast_addr, request.clone()))
                })
                .map(move |framed| {
                    framed
                        .log_errors(LogLevel::Warn, "receiving on service_discovery::discover")
                        .filter_map(move |response| handle_response(response, &anon_decrypt_ctx))
                        .into_boxed()
                })
        })
        .into_boxed()
}

fn handle_response<T: Serialize + DeserializeOwned>(
    response: (SocketAddr, Result<DiscoveryMsg, SerialisationError>),
    anon_decrypt_ctx: &CryptoContext,
) -> Option<(Ipv4Addr, T)> {
    match response {
        (addr, Ok(DiscoveryMsg::Response(response))) => {
            let ip = match addr.ip() {
                IpAddr::V4(ip) => ip,
                _ => unreachable!(),
            };
            match anon_decrypt_ctx.decrypt(&response) {
                Ok(response) => Some((ip, response)),
                Err(e) => {
                    warn!("Failed to decrypt service discovery response: {}", e);
                    None
                }
            }
        }
        (_, Ok(..)) => None,
        (addr, Err(e)) => {
            warn!("Error deserialising message from {}: {}", addr, e);
            None
        }
    }
}
