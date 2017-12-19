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

use futures::sync::mpsc::{self, UnboundedSender};
use log::LogLevel;

use net::listener::SocketIncoming;
use net::peer::connect::{CRUST_REQ_HEADER, connect};
use net::peer::connect::BootstrapAcceptor;
use net::peer::connect::handshake_message::{BootstrapRequest, ConnectRequest, HandshakeMessage};
use p2p::{ECHO_REQ, tcp_respond_with_addr};
use priv_prelude::*;
use std::sync::{Arc, Mutex};
use tokio_io;

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
        handle.spawn(handle_incoming_connections(handle, incoming, &inner));
        Demux { inner: inner }
    }

    pub fn bootstrap_acceptor(
        &self,
        handle: &Handle,
        config: &ConfigFile,
        our_uid: UID,
    ) -> BootstrapAcceptor<UID> {
        let (acceptor, peer_tx) = BootstrapAcceptor::new(handle, config, our_uid);
        let mut bootstrap_handler = unwrap!(self.inner.bootstrap_handler.lock());
        *bootstrap_handler = Some(peer_tx);
        acceptor
    }

    pub fn connect(
        &self,
        handle: &Handle,
        name_hash: NameHash,
        our_info: PrivConnectionInfo<UID>,
        their_info: PubConnectionInfo<UID>,
        config: &ConfigFile,
    ) -> BoxFuture<Peer<UID>, ConnectError> {
        let their_uid = their_info.id;
        let peer_rx = {
            let (peer_tx, peer_rx) = mpsc::unbounded();
            let mut connection_handler = unwrap!(self.inner.connection_handler.lock());
            let _ = connection_handler.insert(their_uid, peer_tx);
            peer_rx
        };

        connect(handle, name_hash, our_info, their_info, config, peer_rx)
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum IncomingError {
        Io(e: io::Error) {
            description("io error accepting incoming connection")
            display("io error accepting incoming connection: {}", e)
            cause(e)
        }
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
) -> BoxFuture<(), ()> {
    let inner = Arc::clone(inner);
    let handle = handle.clone();
    incoming
        .map_err(IncomingError::Io)
        .for_each(move |(stream, addr)| {
            let handle_cloned = handle.clone();
            let inner_cloned = Arc::clone(&inner);

            let header = [0u8; 8];
            tokio_io::io::read_exact(stream, header)
                .map_err(IncomingError::Io)
                .and_then(move |(stream, header)| {
                    handle_message_by_header(&handle_cloned, inner_cloned, stream, addr, header)
                })
        })
        .log_error(LogLevel::Error, "Failed to accept incoming connections!")
        .infallible()
        .into_boxed()
}

/// Dispatch different message handler based on header.
fn handle_message_by_header<UID: Uid>(
    handle: &Handle,
    inner: Arc<DemuxInner<UID>>,
    stream: PaStream,
    addr: PaAddr,
    header: [u8; 8],
) -> BoxFuture<(), IncomingError> {
    match header {
        ECHO_REQ => respond_with_addr(stream, addr),
        CRUST_REQ_HEADER => {
            let socket: Socket<HandshakeMessage<UID>> = Socket::wrap_pa(handle, stream, addr);
            handle_incoming_socket(handle, inner, socket)
        }
        _ => future::err(IncomingError::UnexpectedMessage).into_boxed(),
    }
}

fn respond_with_addr(stream: PaStream, addr: PaAddr) -> BoxFuture<(), IncomingError> {
    match (stream, addr) {
        (PaStream::Tcp(stream), PaAddr::Tcp(addr)) => {
            tcp_respond_with_addr(stream, addr)
                .map_err(IncomingError::Io)
                .map(|_stream| ())
                .into_boxed()
        }
        // TODO(povilas): handle UDP requests
        _ => future::err(IncomingError::UnexpectedMessage).into_boxed(),
    }
}

/// This methods is called when connection sends valid 8 byte header.
fn handle_incoming_socket<UID: Uid>(
    handle: &Handle,
    inner: Arc<DemuxInner<UID>>,
    socket: Socket<HandshakeMessage<UID>>,
) -> BoxFuture<(), IncomingError> {
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
                HandshakeMessage::Connect(connect_request) => {
                    let connection_handler_map = unwrap!(inner.connection_handler.lock());
                    if let Some(connection_handler) =
                        connection_handler_map.get(&connect_request.uid)
                    {
                        let _ = connection_handler.unbounded_send((socket, connect_request));
                    }
                    future::ok(()).into_boxed()
                }
                _ => future::err(IncomingError::UnexpectedMessage).into_boxed(),
            }
        })
        .into_boxed()
}
