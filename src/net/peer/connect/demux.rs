// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::CONNECTIONS_TIMEOUT;
use future_utils::mpsc::{self, UnboundedReceiver, UnboundedSender};
use log::LogLevel;
use lru_time_cache::LruCache;
use net::listener::SocketIncoming;
use net::peer::connect::connect;
#[cfg(feature = "connections_info")]
use net::peer::connect::connect_all;
use net::peer::connect::handshake_message::{BootstrapRequest, ConnectRequest, HandshakeMessage};
use net::peer::connect::BootstrapAcceptor;
use priv_prelude::*;
use std::sync::{Arc, Mutex};

/// Don't keep incoming connections much longer than the attempted connection timeout.
const INCOMING_CONNECTIONS_TIMEOUT: u64 = CONNECTIONS_TIMEOUT + 10;

/// How many incoming connections do we allow to buffer in our queues.
const MAX_INCOMING_CONNECTIONS_BACKLOG: usize = 128;

/// Demultiplexes the incoming stream of connections on the main listener and routes them to either
/// the bootstrap acceptor (if there is one), or to the appropriate connection handler.
#[derive(Clone)]
pub struct Demux {
    inner: Arc<DemuxInner>,
}

/// `BootstrapRequest` paired with stream object.
pub type BootstrapMessage = (PaStream, BootstrapRequest);

/// `ConnectRequest` paired with stream object.
pub type ConnectMessage = (PaStream, ConnectRequest);

struct DemuxInner {
    bootstrap_handler: Mutex<Option<UnboundedSender<BootstrapMessage>>>,
    connection_handler: Mutex<LruCache<u64, UnboundedSender<ConnectMessage>>>,
    available_connections: Mutex<LruCache<u64, ConnectMessage>>,
    handle: Handle,
    bootstrap_cache: BootstrapCache,
}

impl Demux {
    /// Create a demultiplexer from a stream of incoming peers.
    pub fn new(
        handle: &Handle,
        incoming: SocketIncoming,
        bootstrap_cache: &BootstrapCache,
    ) -> Demux {
        let inner = Arc::new(DemuxInner {
            bootstrap_handler: Mutex::new(None),
            connection_handler: Mutex::new(LruCache::with_expiry_duration(Duration::from_secs(
                INCOMING_CONNECTIONS_TIMEOUT,
            ))),
            available_connections: Mutex::new(LruCache::with_expiry_duration(Duration::from_secs(
                INCOMING_CONNECTIONS_TIMEOUT,
            ))),
            handle: handle.clone(),
            bootstrap_cache: bootstrap_cache.clone(),
        });
        handle.spawn(handle_incoming_connections(handle, incoming, &inner));
        Demux { inner }
    }

    pub fn bootstrap_acceptor(
        &self,
        config: &ConfigFile,
        our_uid: PublicEncryptKey,
    ) -> BootstrapAcceptor {
        let (acceptor, peer_tx) = BootstrapAcceptor::new(&self.inner.handle, config, our_uid);
        let mut bootstrap_handler = unwrap!(self.inner.bootstrap_handler.lock());
        *bootstrap_handler = Some(peer_tx);
        acceptor
    }

    pub fn connect<C>(
        &self,
        name_hash: NameHash,
        our_info: PrivConnectionInfo,
        conn_info_rx: C,
        config: &ConfigFile,
    ) -> BoxFuture<Peer, ConnectError>
    where
        C: Stream<Item = PubConnectionInfo>,
        C: 'static,
    {
        let peer_rx = self.direct_conn_receiver(our_info.connection_id);
        connect(
            &self.inner.handle,
            name_hash,
            our_info,
            conn_info_rx,
            config,
            peer_rx,
            &self.inner.bootstrap_cache,
        )
    }

    /// Attempt all possible connection variations and return the results.
    #[cfg(feature = "connections_info")]
    pub fn connect_all<C>(
        &self,
        our_conn_info: PrivConnectionInfo,
        conn_info_rx: C,
        config: &ConfigFile,
    ) -> BoxStream<ConnectionResult, SingleConnectionError>
    where
        C: Stream<Item = PubConnectionInfo>,
        C: 'static,
    {
        let peer_rx = self.direct_conn_receiver(our_conn_info.connection_id);
        connect_all(
            &self.inner.handle,
            our_conn_info,
            conn_info_rx,
            config,
            peer_rx,
            &self.inner.bootstrap_cache,
        )
    }

    /// If there's already available connection for given peer ID, returns connection receiver
    /// that immediately gets connection. Otherwise, returned connection receiver is in waiting
    /// state and when new connection with given peer ID arrives, it will be sent to receiver.
    fn direct_conn_receiver(&self, connection_id: u64) -> UnboundedReceiver<ConnectMessage> {
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
        Read(e: PaStreamReadError) {
            description("error reading from stream")
            display("error reading from stream: {}", e)
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

fn handle_incoming_connections(
    handle: &Handle,
    incoming: SocketIncoming,
    inner: &Arc<DemuxInner>,
) -> BoxFuture<(), ()> {
    let inner = Arc::clone(inner);
    let handle = handle.clone();
    incoming
        .log_errors(LogLevel::Error, "SocketIncoming errored!")
        .map(move |stream| {
            let inner = Arc::clone(&inner);
            handle_incoming_socket(&handle, inner, stream)
        }).buffer_unordered(MAX_INCOMING_CONNECTIONS_BACKLOG)
        .for_each(|()| Ok(()))
        .infallible()
        .into_boxed()
}

/// This methods is called when connection sends valid 8 byte header.
fn handle_incoming_socket(
    handle: &Handle,
    inner: Arc<DemuxInner>,
    stream: PaStream,
) -> BoxFuture<(), Void> {
    stream
        .recv_serialized()
        .map_err(IncomingError::Read)
        .with_timeout(Duration::from_secs(10), handle)
        .and_then(|res| res.ok_or(IncomingError::TimedOut))
        .and_then(move |(msg_opt, stream)| {
            let msg = match msg_opt {
                Some(msg) => msg,
                None => return future::err(IncomingError::Disconnected).into_boxed(),
            };
            match msg {
                HandshakeMessage::BootstrapRequest(bootstrap_request) => {
                    let bootstrap_handler_opt = unwrap!(inner.bootstrap_handler.lock());
                    if let Some(bootstrap_handler) = bootstrap_handler_opt.as_ref() {
                        let _ = bootstrap_handler.unbounded_send((stream, bootstrap_request));
                    }
                    future::ok(()).into_boxed()
                }
                HandshakeMessage::Connect(conn_request) => {
                    handle_connect_request(&inner, stream, conn_request)
                }
                _ => future::err(IncomingError::UnexpectedMessage).into_boxed(),
            }
        }).log_error(LogLevel::Error, "Failed to accept incoming connection")
        .into_boxed()
}

fn handle_connect_request(
    inner: &Arc<DemuxInner>,
    stream: PaStream,
    connect_request: ConnectRequest,
) -> BoxFuture<(), IncomingError> {
    let mut connection_handler_map = unwrap!(inner.connection_handler.lock());
    match connection_handler_map.get(&connect_request.connection_id) {
        Some(conn_handler) => {
            let _ = conn_handler.unbounded_send((stream, connect_request));
        }
        None => {
            let mut available_conns = unwrap!(inner.available_connections.lock());
            let _ =
                available_conns.insert(connect_request.connection_id, (stream, connect_request));
        }
    };
    future::ok(()).into_boxed()
}
