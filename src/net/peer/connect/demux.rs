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

use super::CONNECTIONS_TIMEOUT;
use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use log::LogLevel;
use lru_time_cache::LruCache;
use net::listener::SocketIncoming;
use net::peer::connect::BootstrapAcceptor;
use net::peer::connect::connect;
use net::peer::connect::handshake_message::{BootstrapRequest, ConnectRequest, HandshakeMessage};
use priv_prelude::*;
use rust_sodium::crypto::box_::SecretKey;
use std::sync::{Arc, Mutex};

/// Don't keep incoming connections much longer than the attempted connection timeout.
const INCOMING_CONNECTIONS_TIMEOUT: u64 = CONNECTIONS_TIMEOUT + 10;

/// How many incoming connections do we allow to buffer in our queues.
const MAX_INCOMING_CONNECTIONS_BACKLOG: usize = 128;

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
    connection_handler: Mutex<LruCache<u64, UnboundedSender<ConnectMessage<UID>>>>,
    available_connections: Mutex<LruCache<u64, ConnectMessage<UID>>>,
    handle: Handle,
    bootstrap_cache: BootstrapCache,
}

impl<UID: Uid> Demux<UID> {
    /// Create a demultiplexer from a stream of incoming peers.
    pub fn new(
        handle: &Handle,
        incoming: SocketIncoming,
        crypto_ctx: CryptoContext,
        bootstrap_cache: &BootstrapCache,
    ) -> Demux<UID> {
        let inner = Arc::new(DemuxInner {
            bootstrap_handler: Mutex::new(None),
            connection_handler: Mutex::new(LruCache::with_expiry_duration(Duration::from_secs(
                INCOMING_CONNECTIONS_TIMEOUT,
            ))),
            available_connections: Mutex::new(LruCache::with_expiry_duration(
                Duration::from_secs(INCOMING_CONNECTIONS_TIMEOUT),
            )),
            handle: handle.clone(),
            bootstrap_cache: bootstrap_cache.clone(),
        });
        handle.spawn(handle_incoming_connections(
            handle,
            incoming,
            &inner,
            crypto_ctx,
        ));
        Demux { inner: inner }
    }

    pub fn bootstrap_acceptor(
        &self,
        config: &ConfigFile,
        our_uid: UID,
        our_sk: SecretKey,
    ) -> BootstrapAcceptor<UID> {
        let (acceptor, peer_tx) =
            BootstrapAcceptor::new(&self.inner.handle, config, our_uid, our_sk);
        let mut bootstrap_handler = unwrap!(self.inner.bootstrap_handler.lock());
        *bootstrap_handler = Some(peer_tx);
        acceptor
    }

    pub fn connect(
        &self,
        name_hash: NameHash,
        our_info: PrivConnectionInfo<UID>,
        their_info: PubConnectionInfo<UID>,
        config: &ConfigFile,
    ) -> BoxFuture<Peer<UID>, ConnectError> {
        let peer_rx = self.direct_conn_receiver(our_info.connection_id);
        connect(
            &self.inner.handle,
            name_hash,
            our_info,
            their_info,
            config,
            peer_rx,
            &self.inner.bootstrap_cache,
        )
    }

    /// If there's already available connection for given peer ID, returns connection receiver
    /// that immediately gets connection. Otherwise, returned connection receiver is in waiting
    /// state and when new connection with given peer ID arrives, it will be sent to receiver.
    fn direct_conn_receiver(&self, connection_id: u64) -> UnboundedReceiver<ConnectMessage<UID>> {
        let (peer_tx, peer_rx) = mpsc::unbounded();
        let mut available_conns = unwrap!(self.inner.available_connections.lock());
        match available_conns.remove(&connection_id) {
            Some(conn) => {
                let _ = peer_tx.unbounded_send(conn);
            }
            None => {
                let mut connection_handler = unwrap!(self.inner.connection_handler.lock());
                let _ = connection_handler.insert(connection_id, peer_tx);
            }
        };
        peer_rx
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

fn handle_incoming_connections<UID: Uid>(
    handle: &Handle,
    incoming: SocketIncoming,
    inner: &Arc<DemuxInner<UID>>,
    crypto_ctx: CryptoContext,
) -> BoxFuture<(), ()> {
    let inner = Arc::clone(inner);
    let handle = handle.clone();
    incoming
        .log_errors(LogLevel::Error, "SocketIncoming errored!")
        .map(move |(stream, addr)| {
            let socket: Socket<HandshakeMessage<UID>> =
                Socket::wrap_pa(&handle, stream, addr, crypto_ctx.clone());
            let inner = Arc::clone(&inner);
            handle_incoming_socket(&handle, inner, socket)
        })
        .buffer_unordered(MAX_INCOMING_CONNECTIONS_BACKLOG)
        .for_each(|()| Ok(()))
        .infallible()
        .into_boxed()
}

/// This methods is called when connection sends valid 8 byte header.
fn handle_incoming_socket<UID: Uid>(
    handle: &Handle,
    inner: Arc<DemuxInner<UID>>,
    socket: Socket<HandshakeMessage<UID>>,
) -> BoxFuture<(), Void> {
    socket
        .into_future()
        .map_err(|(e, _s)| IncomingError::Socket(e))
        .with_timeout(Duration::from_secs(10), handle)
        .and_then(|res| res.ok_or(IncomingError::TimedOut))
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
                HandshakeMessage::Connect(conn_request) => {
                    handle_connect_request(&inner, socket, conn_request)
                }
                _ => future::err(IncomingError::UnexpectedMessage).into_boxed(),
            }
        })
        .log_error(LogLevel::Error, "Failed to accept incoming connection")
        .into_boxed()
}

fn handle_connect_request<UID: Uid>(
    inner: &Arc<DemuxInner<UID>>,
    socket: Socket<HandshakeMessage<UID>>,
    connect_request: ConnectRequest<UID>,
) -> BoxFuture<(), IncomingError> {
    let mut connection_handler_map = unwrap!(inner.connection_handler.lock());
    match connection_handler_map.get(&connect_request.connection_id) {
        Some(conn_handler) => {
            let _ = conn_handler.unbounded_send((socket, connect_request));
        }
        None => {
            let mut available_conns = unwrap!(inner.available_connections.lock());
            let _ =
                available_conns.insert(connect_request.connection_id, (socket, connect_request));
        }
    };
    future::ok(()).into_boxed()
}
