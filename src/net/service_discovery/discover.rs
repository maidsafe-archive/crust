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


use futures::{Async, Future, Sink, Stream};
use futures::sink;
use futures::stream::StreamFuture;

use maidsafe_utilities::serialisation::SerialisationError;
use net::service_discovery::msg::DiscoveryMsg;
use priv_prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::{io, mem};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio_core::net::{UdpFramed, UdpSocket};
use tokio_core::reactor::Handle;
use util::SerdeUdpCodec;
use void::Void;

pub fn discover<T>(
    handle: &Handle,
    port: u16,
    our_pk: PublicKey,
    our_sk: SecretKey,
) -> io::Result<Discover<T>>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{

    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
    let socket = UdpSocket::bind(&bind_addr, handle)?;
    socket.set_broadcast(true)?;
    let framed = socket.framed(SerdeUdpCodec::new());

    let request = DiscoveryMsg::Request(our_pk);
    let broadcast_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), port));
    let writing = framed.send((broadcast_addr, request));

    let anon_decrypt_ctx = CryptoContext::anonymous_decrypt(our_pk, our_sk);

    Ok(Discover {
        state: DiscoverState::Writing { writing },
        anon_decrypt_ctx,
        _ph: PhantomData,
    })
}

pub struct Discover<T> {
    state: DiscoverState,
    anon_decrypt_ctx: CryptoContext,
    _ph: PhantomData<T>,
}

// The only large size difference between variance is because of `Invalid` variant.
// This variant is not really used, hence it makes sense to disable this lint.
//#[cfg_attr(feature = "clippy", allow(large_enum_variant))]
#[allow(unknown_lints)]
#[allow(large_enum_variant)]
enum DiscoverState {
    Reading { reading: StreamFuture<UdpFramed<SerdeUdpCodec<DiscoveryMsg>>>, },
    Writing { writing: sink::Send<UdpFramed<SerdeUdpCodec<DiscoveryMsg>>>, },
    Invalid,
}

impl<T> Discover<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    /// Handles service discovery response: deserializes and decrypts it.
    /// None is returned on failure.
    fn handle_response(
        &self,
        response: Option<(SocketAddr, Result<DiscoveryMsg, SerialisationError>)>,
    ) -> Option<(Ipv4Addr, T)> {
        match response {
            Some((addr, Ok(DiscoveryMsg::Response(response)))) => {
                let ip = match addr.ip() {
                    IpAddr::V4(ip) => ip,
                    _ => unreachable!(),
                };
                match self.anon_decrypt_ctx.decrypt(&response) {
                    Ok(response) => Some((ip, response)),
                    Err(e) => {
                        warn!("Failed to decrypt service discovery response: {}", e);
                        None
                    }
                }
            }
            Some((_, Ok(..))) => None,
            Some((addr, Err(e))) => {
                warn!("Error deserialising message from {}: {}", addr, e);
                None
            }
            None => unreachable!(),
        }
    }
}

impl<T> Stream for Discover<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    type Item = (Ipv4Addr, T);
    type Error = Void;

    fn poll(&mut self) -> Result<Async<Option<(Ipv4Addr, T)>>, Void> {
        let mut state = mem::replace(&mut self.state, DiscoverState::Invalid);
        let ret = loop {
            match state {
                DiscoverState::Reading { mut reading } => {
                    if let Async::Ready((response, framed)) =
                        unwrap!(reading.poll().map_err(|(e, _)| e))
                    {
                        state = DiscoverState::Reading { reading: framed.into_future() };
                        let resp_item = self.handle_response(response);
                        if let Some(item) = resp_item {
                            break Async::Ready(Some(item));
                        }
                    } else {
                        state = DiscoverState::Reading { reading };
                        break Async::NotReady;
                    }
                }
                DiscoverState::Writing { mut writing } => {
                    if let Async::Ready(framed) = unwrap!(writing.poll()) {
                        state = DiscoverState::Reading { reading: framed.into_future() };
                        continue;
                    } else {
                        state = DiscoverState::Writing { writing };
                        break Async::NotReady;
                    }
                }
                DiscoverState::Invalid => panic!(),
            }
        };
        self.state = state;
        Ok(ret)
    }
}
