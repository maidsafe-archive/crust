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

use bytes::Bytes;
use futures::sync::mpsc::{self, UnboundedSender};
use log::LogLevel;

use net::listener::SocketIncoming;
use net::peer::connect::BootstrapAcceptor;
use net::peer::connect::connect::connect;
use net::peer::connect::handshake_message::{BootstrapRequest, ConnectRequest, HandshakeMessage};
use net::peer::connect::stun;
use priv_prelude::*;
use std::sync::{Arc, Mutex};

/// Demultiplexes the incoming stream of connections on the main listener and routes them to either
/// the bootstrap acceptor (if there is one), or to the appropriate connection handler.
pub struct Demux<UID: Uid> {
    inner: Arc<DemuxInner<UID>>,
}

/// `BootstrapRequest` paired with socket object.
pub type BootstrapMessage<UID> = (Socket<HandshakeMessage<UID>>, BootstrapRequest<UID>);

/// `ConnectRequest` paired with socket object.
pub type ConnectMessage<UID> = (Socket<HandshakeMessage<UID>>, ConnectRequest<UID>);

struct DemuxInner<UID: Uid> {
    bootstrap_handler: Mutex<Option<UnboundedSender<BootstrapMessage<UID>>>>,
    connection_handler: Mutex<HashMap<UID, UnboundedSender<ConnectMessage<UID>>>>,
}

impl<UID: Uid> Demux<UID> {
    /// Create a demultiplexer from a stream of incoming peers.
    pub fn new(handle: &Handle, incoming: SocketIncoming) -> Demux<UID> {
        let inner = Arc::new(DemuxInner {
            bootstrap_handler: Mutex::new(None),
            connection_handler: Mutex::new(HashMap::new()),
        });
        let inner_cloned = Arc::clone(&inner);
        let handle0 = handle.clone();
        let handler_task = {
            incoming
            .log_errors(LogLevel::Error, "listener errored!")
            .map(move |socket| {
                let socket = socket.change_message_type::<HandshakeMessage<UID>>();

                handle_incoming(&handle0, Arc::clone(&inner_cloned), socket)
                .log_error(LogLevel::Debug, "handling incoming connection")
            })
            .buffer_unordered(128)
            .for_each(|()| Ok(()))
            .infallible()
        };
        handle.spawn(handler_task);
        Demux { inner: inner }
    }

    pub fn bootstrap_acceptor(
        &self,
        handle: &Handle,
        config: ConfigFile,
        our_uid: UID,
    ) -> BootstrapAcceptor<UID> {
        let (acceptor, peer_tx) = BootstrapAcceptor::new(handle, config, our_uid);
        let mut bootstrap_handler = unwrap!(self.inner.bootstrap_handler.lock());
        *bootstrap_handler = Some(peer_tx);
        acceptor
    }

    pub fn connect<C>(
        &self,
        handle: &Handle,
        name_hash: NameHash,
        our_id: UID,
        relay_channel: C,
        config: ConfigFile,
    ) -> BoxFuture<Peer<UID>, ConnectError>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static,
    {
        // TODO(povilas): add direct connection handler
        connect(handle, name_hash, our_id, relay_channel, config)
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum IncomingError {
        TimedOut {
            description("timed out waiting for the peer to send their request")
        }
        Socket(e: SocketError) {
            description("error on the socket")
            display("error on the socket: {}", e)
            cause(e)
        }
        UnexpectedMessage {
            description("the peer sent an unexpected message type")
        }
        Disconnected {
            description("the remote peer disconnected")
        }
    }
}

fn handle_incoming<UID: Uid>(
    handle: &Handle,
    inner: Arc<DemuxInner<UID>>,
    socket: Socket<HandshakeMessage<UID>>,
) -> BoxFuture<(), IncomingError> {
    socket
        .into_future()
        .map_err(|(e, _s)| IncomingError::Socket(e))
        .with_timeout(handle, Duration::from_secs(10), IncomingError::TimedOut)
        .and_then(move |(msg_opt, socket)| {
            let msg = match msg_opt {
                Some(msg) => msg,
                None => return future::err(IncomingError::Disconnected).into_boxed(),
            };
            match msg {
                HandshakeMessage::BootstrapRequest(bootstrap_request) => {
                    let bootstrap_handler_opt = unwrap!(inner.bootstrap_handler.lock());
                    if let Some(bootstrap_handler) = bootstrap_handler_opt.as_ref() {
                        let _ = bootstrap_handler.unbounded_send((socket, bootstrap_request));
                    }
                    future::ok(()).into_boxed()
                }
                HandshakeMessage::Connect(connect_request) => {
                    let connection_handler_map = unwrap!(inner.connection_handler.lock());
                    if let Some(connection_handler) =
                        connection_handler_map.get(&connect_request.uid)
                    {
                        let _ = connection_handler.unbounded_send((socket, connect_request));
                    }
                    future::ok(()).into_boxed()
                }
                HandshakeMessage::EchoAddrReq => {
                    stun::stun_respond(socket)
                        .map_err(IncomingError::Socket)
                        .into_boxed()
                }
                _ => future::err(IncomingError::UnexpectedMessage).into_boxed(),
            }
        })
        .into_boxed()
}
