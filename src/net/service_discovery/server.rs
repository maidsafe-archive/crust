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
use future_utils::FutureExt;
use futures::sink;
use futures::stream::StreamFuture;
use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Sink, Stream};
use maidsafe_utilities::serialisation::SerialisationError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::{io, mem};
use tokio_core::net::{UdpFramed, UdpSocket};
use tokio_core::reactor::Handle;
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
#[allow(clippy::large_enum_variant)]
enum ServerTaskState {
    Reading {
        reading: StreamFuture<UdpFramed<SerdeUdpCodec<DiscoveryMsg>>>,
    },
    Writing {
        writing: sink::Send<UdpFramed<SerdeUdpCodec<DiscoveryMsg>>>,
    },
    Invalid,
}

impl<T> Server<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    #[allow(clippy::new_ret_no_self)]
    pub fn new(handle: &Handle, port: u16, data: T) -> io::Result<Server<T>> {
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
        let socket = UdpSocket::bind(&bind_addr, handle)?;
        let actual_port = socket.local_addr()?.port();
        let framed = socket.framed(SerdeUdpCodec::new());

        let (data_tx, data_rx) = mpsc::unbounded();

        let state = ServerTaskState::Reading {
            reading: framed.into_future(),
        };
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
        request: (SocketAddr, Result<DiscoveryMsg, SerialisationError>),
        framed: UdpFramed<SerdeUdpCodec<DiscoveryMsg>>,
    ) -> ServerTaskState {
        match request {
            (addr, Ok(DiscoveryMsg::Request(their_pk))) => {
                match their_pk.anonymously_encrypt(&self.data) {
                    Ok(response) => {
                        let response = DiscoveryMsg::Response(BytesMut::from(response));
                        let writing = framed.send((addr, response));
                        return ServerTaskState::Writing { writing };
                    }
                    Err(e) => warn!("Failed to encrypt service discovery response: {}", e),
                }
            }
            (_, Ok(..)) => (),
            (addr, Err(e)) => {
                warn!("Error deserialising message from {}: {}", addr, e);
            }
        }
        ServerTaskState::Reading {
            reading: framed.into_future(),
        }
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
                        state = self.handle_request(unwrap!(request), framed);
                        continue;
                    } else {
                        state = ServerTaskState::Reading { reading };
                        break;
                    }
                }
                ServerTaskState::Writing { mut writing } => {
                    if let Async::Ready(framed) = unwrap!(writing.poll()) {
                        state = ServerTaskState::Reading {
                            reading: framed.into_future(),
                        };
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

            let current_addrs = hashset! {
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
