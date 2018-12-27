// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::net::service_discovery::msg::DiscoveryMsg;
use crate::priv_prelude::*;
use crate::util::SerdeUdpCodec;
use futures::{Future, Sink, Stream};
use get_if_addrs::{self, IfAddr};
use maidsafe_utilities::serialisation::SerialisationError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::net::Ipv4Addr;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::Handle;

/// Returns IP address and listener addresses of a first node to respond to service discovery
/// request.
pub fn discover<T>(
    handle: &Handle,
    port: u16,
    our_sk: SecretEncryptKey,
    our_pk: PublicEncryptKey,
) -> IoFuture<BoxStream<(Ipv4Addr, T), Void>>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    let bind_addr = addr!("0.0.0.0:0");
    let request = DiscoveryMsg::Request(our_pk);

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
                        .filter_map(move |response| handle_response(response, &our_sk, &our_pk))
                        .into_boxed()
                })
        })
        .into_boxed()
}

fn handle_response<T: Serialize + DeserializeOwned>(
    response: (SocketAddr, Result<DiscoveryMsg, SerialisationError>),
    our_sk: &SecretEncryptKey,
    our_pk: &PublicEncryptKey,
) -> Option<(Ipv4Addr, T)> {
    match response {
        (addr, Ok(DiscoveryMsg::Response(response))) => {
            let ip = match addr.ip() {
                IpAddr::V4(ip) => ip,
                _ => unreachable!(),
            };
            match our_sk.anonymously_decrypt(&response, our_pk) {
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
