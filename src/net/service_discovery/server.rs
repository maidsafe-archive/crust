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

use net::service_discovery::msg::DiscoveryMsg;
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
    state: ServerTaskState<T>,
}

enum ServerTaskState<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    Reading { reading: StreamFuture<UdpFramed<SerdeUdpCodec<DiscoveryMsg<T>>>>, },
    Writing { writing: sink::Send<UdpFramed<SerdeUdpCodec<DiscoveryMsg<T>>>>, },
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
                    if let Async::Ready((res, framed)) =
                        unwrap!(reading.poll().map_err(|(e, _)| e))
                    {
                        match res {
                            Some((addr, Ok(DiscoveryMsg::Request(_)))) => {
                                let response = DiscoveryMsg::Response(self.data.clone());
                                let writing = framed.send((addr, response));
                                state = ServerTaskState::Writing { writing };
                                continue;
                            }
                            Some((_, Ok(..))) => (),
                            Some((addr, Err(e))) => {
                                warn!("Error deserialising message from {}: {}", addr, e);
                            }
                            None => unreachable!(),
                        }
                        state = ServerTaskState::Reading { reading: framed.into_future() };
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
