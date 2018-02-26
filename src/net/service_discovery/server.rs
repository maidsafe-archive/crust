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


use future_utils::FutureExt;
use futures::{Async, Future, Sink, Stream};
use futures::sink;
use futures::stream::StreamFuture;
use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use maidsafe_utilities::serialisation::SerialisationError;
use net::service_discovery::msg::DiscoveryMsg;
use priv_prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::{io, mem};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio_core::net::{UdpFramed, UdpSocket};
use tokio_core::reactor::Handle;
use util::SerdeUdpCodec;
use void::Void;

pub struct Server<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    port: u16,
    data_tx: UnboundedSender<T>,
}

struct ServerTask<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    data_rx: UnboundedReceiver<T>,
    data: T,
    state: ServerTaskState,
}

// The only large size difference between variance is because of `Invalid` variant.
// This variant is not really used, hence it makes sense to disable this lint.
#[allow(unknown_lints)]
#[allow(large_enum_variant)]
enum ServerTaskState {
    Reading { reading: StreamFuture<UdpFramed<SerdeUdpCodec<DiscoveryMsg>>>, },
    Writing { writing: sink::Send<UdpFramed<SerdeUdpCodec<DiscoveryMsg>>>, },
    Invalid,
}

impl<T> Server<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    pub fn new(handle: &Handle, port: u16, data: T) -> io::Result<Server<T>> {
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
        let socket = UdpSocket::bind(&bind_addr, handle)?;
        let actual_port = socket.local_addr()?.port();
        let framed = socket.framed(SerdeUdpCodec::new());

        let (data_tx, data_rx) = mpsc::unbounded();

        let state = ServerTaskState::Reading { reading: framed.into_future() };
        let server_task = ServerTask {
            data_rx,
            data,
            state,
        };
        handle.spawn(server_task.infallible());

        let server_ctl = Server {
            port: actual_port,
            data_tx,
        };
        Ok(server_ctl)
    }

    pub fn set_data(&mut self, data: T) {
        unwrap!(self.data_tx.unbounded_send(data));
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl<T> ServerTask<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    /// Handles service discovery request.
    /// Returns new server state: either reading or writing.  In case of any errors server remains
    /// in reading state.
    fn handle_request(
        &self,
        request: Option<(SocketAddr, Result<DiscoveryMsg, SerialisationError>)>,
        framed: UdpFramed<SerdeUdpCodec<DiscoveryMsg>>,
    ) -> ServerTaskState {
        match request {
            Some((addr, Ok(DiscoveryMsg::Request(their_pk)))) => {
                let crypto_ctx = CryptoContext::anonymous_encrypt(their_pk);
                match crypto_ctx.encrypt(&self.data) {
                    Ok(response) => {
                        let response = DiscoveryMsg::Response(response);
                        let writing = framed.send((addr, response));
                        return ServerTaskState::Writing { writing };
                    }
                    Err(e) => warn!("Failed to encrypt service discovery response: {}", e),
                }
            }
            Some((_, Ok(..))) => (),
            Some((addr, Err(e))) => {
                warn!("Error deserialising message from {}: {}", addr, e);
            }
            None => unreachable!(),
        }
        ServerTaskState::Reading { reading: framed.into_future() }
    }
}

impl<T> Future for ServerTask<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    type Item = ();
    type Error = Void;

    fn poll(&mut self) -> Result<Async<()>, Void> {
        loop {
            match self.data_rx.poll().map_err(|()| unreachable!())? {
                Async::Ready(Some(data)) => self.data = data,
                Async::Ready(None) => return Ok(Async::Ready(())),
                Async::NotReady => break,
            }
        }

        let mut state = mem::replace(&mut self.state, ServerTaskState::Invalid);
        loop {
            match state {
                ServerTaskState::Reading { mut reading } => {
                    if let Async::Ready((request, framed)) =
                        unwrap!(reading.poll().map_err(|(e, _)| e))
                    {
                        state = self.handle_request(request, framed);
                        continue;
                    } else {
                        state = ServerTaskState::Reading { reading };
                        break;
                    }
                }
                ServerTaskState::Writing { mut writing } => {
                    if let Async::Ready(framed) = unwrap!(writing.poll()) {
                        state = ServerTaskState::Reading { reading: framed.into_future() };
                        continue;
                    } else {
                        state = ServerTaskState::Writing { writing };
                        break;
                    };
                }
                ServerTaskState::Invalid => panic!(),
            }
        }
        self.state = state;

        Ok(Async::NotReady)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_core::reactor::Core;

    mod server {
        use super::*;

        #[test]
        fn when_client_sends_random_plain_text_it_sends_nothing_back() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();

            let current_addrs =
                hashset!{
                tcp_addr!("1.2.3.4:4000"),
                tcp_addr!("1.2.3.5:5000"),
            };
            let server = unwrap!(Server::new(&handle, 0, current_addrs));
            let server_addr = SocketAddr::new(ip!("127.0.0.1"), server.port);

            let socket = unwrap!(UdpSocket::bind(&addr!("0.0.0.0:0"), &handle));
            let send_text = socket
                .send_dgram(b"random data", server_addr)
                .and_then(|(socket, _buf)| socket.recv_dgram(Vec::new()))
                .map(|(_socket, buf, _bytes_received, _from)| buf)
                .with_timeout(Duration::from_secs(2), &handle);
            let resp = unwrap!(evloop.run(send_text));

            let timed_out = resp.is_none();
            assert!(timed_out);
        }
    }
}
