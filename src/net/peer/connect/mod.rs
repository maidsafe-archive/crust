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

pub use self::bootstrap::{bootstrap, BootstrapError, Cache as BootstrapCache,
                          CacheError as BootstrapCacheError, ConnectHandshakeError};
pub use self::bootstrap_acceptor::{BootstrapAcceptError, BootstrapAcceptor};
pub use self::connection_info::{P2pConnectionInfo, PrivConnectionInfo, PubConnectionInfo};
pub use self::demux::Demux;
pub use self::ext_reachability::ExternalReachability;
pub use self::handshake_message::{BootstrapDenyReason, BootstrapRequest};

mod bootstrap;
mod connection_info;
mod ext_reachability;
mod demux;
mod handshake_message;
mod bootstrap_acceptor;

use config::PeerInfo;
use future_utils::bi_channel::UnboundedBiChannel;
use futures::sync::mpsc::{SendError, UnboundedReceiver};
use futures::sync::oneshot;
use net::peer;
use net::peer::connect::demux::ConnectMessage;
use net::peer::connect::handshake_message::{ConnectRequest, HandshakeMessage};
use p2p::P2p;
use priv_prelude::*;
use rust_sodium::crypto::box_::{PublicKey, SecretKey};

pub type RendezvousConnectError = PaRendezvousConnectError<Void, SendError<Bytes>>;

// Seconds after which all connections will timeout.
pub const CONNECTIONS_TIMEOUT: u64 = 60;

quick_error! {
    #[derive(Debug)]
    pub enum ConnectError {
        RequestedConnectToSelf {
            description("requested a connection to ourselves")
        }
        Io(e: io::Error) {
            description("io error initiating connection")
            display("io error initiating connection: {}", e)
            cause(e)
        }
        ChooseConnection(e: SocketError) {
            description("socket error when finalising handshake")
            display("socket error when finalising handshake: {}", e)
            cause(e)
        }
        AllConnectionsFailed(v: Vec<SingleConnectionError>) {
            description("all attempts to connect to the remote peer failed")
            display("all {} attempts to connect to the remote peer failed: {:?}", v.len(), v)
        }
        TimedOut {
            description("connection attempt timed out")
        }
        Peer(e: PeerError) {
            description("error on Peer object")
            display("error on Peer object: {}", e)
        }
        NotWhitelisted(ip: IpAddr) {
            description("peer is not whitelisted")
            display("peer {} is not whitelisted", ip)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    #[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
    pub enum SingleConnectionError {
        Io(e: io::Error) {
            description("io error initiating/accepting connection")
            display("io error initiating/accepting connection: {}", e)
            cause(e)
            from()
        }
        Socket(e: SocketError) {
            description("io error socket error")
            display("io error on socket: {}", e)
            cause(e)
        }
        ConnectionDropped {
            description("the connection was dropped by the remote peer")
        }
        InvalidUid(formatted_received_uid: String, formatted_expected_uid: String) {
            description("Peer gave us an unexpected uid")
            display("Peer gave us an unexpected uid: {} != {}",
                    formatted_received_uid, formatted_expected_uid)
        }
        InvalidNameHash(name_hash: NameHash) {
            description("Peer is from a different network")
            display("Peer is from a different network. Invalid name hash == {:?}", name_hash)
        }
        UnexpectedMessage {
            description("Peer sent us an unexpected message variant")
        }
        TimedOut {
            description("connection attempt timed out")
        }
        DeadChannel {
            description("Communication channel was cancelled")
        }
        RendezvousConnect(e: RendezvousConnectError) {
            description("rendezvous connect failed")
            display("rendezvous connect failed: {}", e)
            cause(e)
        }
    }
}

/// Perform a rendezvous connect to a peer. Both peers call this simultaneously using
/// `PubConnectionInfo` they received from the other peer out-of-band.
pub fn connect<UID: Uid>(
    handle: &Handle,
    name_hash: NameHash,
    our_info: PrivConnectionInfo<UID>,
    their_info: PubConnectionInfo<UID>,
    config: &ConfigFile,
    peer_rx: UnboundedReceiver<ConnectMessage<UID>>,
    bootstrap_cache: &BootstrapCache,
) -> BoxFuture<Peer<UID>, ConnectError> {
    let config = config.clone();
    if our_info.id == their_info.id {
        return future::result(Err(ConnectError::RequestedConnectToSelf)).into_boxed();
    }

    for addr in &their_info.for_direct {
        if !config.is_peer_whitelisted(addr.ip(), CrustUser::Node) {
            return future::result(Err(ConnectError::NotWhitelisted(addr.ip()))).into_boxed();
        }
    }

    let their_id = their_info.id;
    let our_connect_request = ConnectRequest {
        connection_id: their_info.connection_id,
        peer_uid: our_info.id,
        peer_pk: our_info.our_pk,
        name_hash: name_hash,
    };
    let our_id = our_info.id;
    let our_sk = our_info.our_sk.clone();

    let all_outgoing_connections = attempt_to_connect(
        handle,
        &config,
        &our_connect_request,
        their_info,
        our_info,
        bootstrap_cache,
    );
    let direct_incoming =
        handshake_incoming_connections(our_connect_request, peer_rx, their_id, our_sk);
    let all_connections = all_outgoing_connections
        .select(direct_incoming)
        .with_timeout(Duration::from_secs(CONNECTIONS_TIMEOUT), handle);
    ChooseOneConnection::new(handle, all_connections, our_id)
        .and_then(move |peer| {
            let ip = peer.ip().map_err(ConnectError::Peer)?;
            if config.is_peer_whitelisted(ip, CrustUser::Node) {
                Ok(peer)
            } else {
                Err(ConnectError::NotWhitelisted(ip))
            }
        })
        .into_boxed()
}

/// Initiates both direct and p2p connections.
fn attempt_to_connect<UID: Uid>(
    handle: &Handle,
    config: &ConfigFile,
    our_connect_request: &ConnectRequest<UID>,
    their_info: PubConnectionInfo<UID>,
    our_info: PrivConnectionInfo<UID>,
    bootstrap_cache: &BootstrapCache,
) -> BoxStream<(Socket<HandshakeMessage<UID>>, UID), SingleConnectionError> {
    let direct_connections = {
        let crypto_ctx = CryptoContext::anonymous_encrypt(their_info.pub_key);
        let handle = handle.clone();
        connect_directly(
            &handle,
            their_info.for_direct,
            their_info.pub_key,
            config,
            bootstrap_cache,
        ).and_then(move |(stream, peer_addr)| {
            Ok(Socket::wrap_pa(
                &handle,
                stream,
                peer_addr,
                crypto_ctx.clone(),
            ))
        })
    };
    let all_connections = if config.rendezvous_connections_disabled() {
        direct_connections.into_boxed()
    } else {
        let crypto_ctx = CryptoContext::authenticated(their_info.pub_key, our_info.our_sk.clone());
        let handle = handle.clone();
        let rendezvous_conn = connect_p2p(our_info.p2p_conn_info, their_info.p2p_conn_info)
            .and_then(move |stream| {
                let peer_addr = stream.peer_addr()?;
                Ok(Socket::wrap_pa(
                    &handle,
                    framed_stream(stream),
                    peer_addr,
                    crypto_ctx,
                ))
            });
        direct_connections
            .select(rendezvous_conn.into_stream())
            .into_boxed()
    };
    handshake_outgoing_connections(
        all_connections,
        our_connect_request.clone(),
        their_info.id,
        their_info.pub_key,
        our_info.our_sk,
    )
}

/// Future that ensures that both peers select the same connection.
/// Takes all pending handshaken connections and chooses the first one successful.
/// Then this connection is wrapped in a `Peer` structure.
/// Depending on service id either initiates connection choice message or waits for one.
struct ChooseOneConnection<S, UID: Uid>
where
    S: Stream<Item = (Socket<HandshakeMessage<UID>>, UID), Error = SingleConnectionError> + 'static,
{
    handle: Handle,
    all_connections: S,
    all_connections_are_done: bool,
    our_uid: UID,
    choose_sent: Option<BoxFuture<(Socket<HandshakeMessage<UID>>, UID), ConnectError>>,
    choose_waiting: Vec<
        BoxFuture<
            (
                Option<HandshakeMessage<UID>>,
                Socket<HandshakeMessage<UID>>,
                UID,
            ),
            SingleConnectionError,
        >,
    >,
    errors: Vec<SingleConnectionError>,
}

impl<S, UID: Uid> ChooseOneConnection<S, UID>
where
    S: Stream<Item = (Socket<HandshakeMessage<UID>>, UID), Error = SingleConnectionError> + 'static,
{
    fn new(handle: &Handle, connections: S, our_uid: UID) -> Self {
        Self {
            handle: handle.clone(),
            all_connections: connections,
            all_connections_are_done: false,
            our_uid,
            choose_sent: None,
            choose_waiting: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Polls all potentially ready connections.
    /// Collects all the errors. If none of connections is ready, returns.
    fn poll_connections(&mut self) {
        while !self.all_connections_are_done {
            match self.all_connections.poll() {
                Ok(Async::Ready(Some((socket, their_uid)))) => {
                    self.on_conn_ready(socket, their_uid)
                }
                Ok(Async::Ready(None)) => {
                    self.all_connections_are_done = true;
                    break;
                }
                Ok(Async::NotReady) => break,
                Err(e) => self.errors.push(e),
            }
        }
    }

    fn on_conn_ready(&mut self, socket: Socket<HandshakeMessage<UID>>, their_uid: UID) {
        if self.our_uid > their_uid {
            self.choose_sent = Some(
                socket
                    .send((0, HandshakeMessage::ChooseConnection))
                    .map_err(ConnectError::ChooseConnection)
                    .map(move |socket| (socket, their_uid))
                    .into_boxed(),
            );
            // we'll take first ready connection
            self.all_connections_are_done = true;
        } else {
            self.choose_waiting.push(
                socket
                    .into_future()
                    .map_err(|(err, _socket)| SingleConnectionError::Socket(err))
                    .map(move |(msg_opt, socket)| (msg_opt, socket, their_uid))
                    .into_boxed(),
            );
        }
    }

    fn send_choose(&mut self) -> Result<Option<Peer<UID>>, ConnectError> {
        let handle = &self.handle;
        if let Some(mut fut) = self.choose_sent.take() {
            match fut.poll() {
                Ok(Async::Ready((socket, their_uid))) => {
                    return Ok(Some(peer::from_handshaken_socket(
                        handle,
                        socket,
                        their_uid,
                        CrustUser::Node,
                    )));
                }
                Ok(Async::NotReady) => self.choose_sent = Some(fut),
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// Wait for the first connection that receives "Choose Connection" message.
    fn recv_choose(&mut self) -> Option<Peer<UID>> {
        let handle = &self.handle;
        let mut i = 0;
        while i < self.choose_waiting.len() {
            match self.choose_waiting[i].poll() {
                Ok(Async::Ready((msg_opt, socket, their_uid))) => match msg_opt {
                    Some(HandshakeMessage::ChooseConnection) => {
                        return Some(peer::from_handshaken_socket(
                            handle,
                            socket,
                            their_uid,
                            CrustUser::Node,
                        ));
                    }
                    None => {
                        self.errors.push(SingleConnectionError::ConnectionDropped);
                        let _ = self.choose_waiting.swap_remove(i);
                    }
                    Some(_msg) => {
                        self.errors.push(SingleConnectionError::UnexpectedMessage);
                        let _ = self.choose_waiting.swap_remove(i);
                    }
                },
                Ok(Async::NotReady) => i += 1,
                Err(e) => {
                    self.errors.push(e);
                    let _ = self.choose_waiting.swap_remove(i);
                }
            }
        }
        None
    }
}

impl<S, UID: Uid> Future for ChooseOneConnection<S, UID>
where
    S: Stream<Item = (Socket<HandshakeMessage<UID>>, UID), Error = SingleConnectionError> + 'static,
{
    type Item = Peer<UID>;
    type Error = ConnectError;

    /// Yields first successful connection.
    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        self.poll_connections();

        match self.send_choose() {
            Ok(Some(peer)) => return Ok(Async::Ready(peer)),
            Err(e) => return Err(e),
            Ok(None) => (),
        }
        if let Some(peer) = self.recv_choose() {
            return Ok(Async::Ready(peer));
        }

        if self.all_connections_are_done && self.choose_sent.is_none()
            && self.choose_waiting.is_empty()
        {
            let errors = mem::replace(&mut self.errors, Vec::new());
            Err(ConnectError::AllConnectionsFailed(errors))
        } else {
            Ok(Async::NotReady)
        }
    }
}

fn connect_directly(
    evloop_handle: &Handle,
    addrs: Vec<PaAddr>,
    their_pk: PublicKey,
    config: &ConfigFile,
    bootstrap_cache: &BootstrapCache,
) -> BoxStream<(FramedPaStream, PaAddr), SingleConnectionError> {
    let bootstrap_cache = bootstrap_cache.clone();
    let connections = addrs
        .into_iter()
        .map(move |addr| {
            let bootstrap_cache1 = bootstrap_cache.clone();
            let bootstrap_cache2 = bootstrap_cache.clone();
            PaStream::direct_connect(evloop_handle, &addr, their_pk, config)
                .map(move |conn| {
                    bootstrap_cache1.put(&PeerInfo::new(addr, their_pk));
                    let _ = bootstrap_cache1
                        .commit()
                        .map_err(|e| error!("Failed to commit bootstrap cache: {}", e));
                    conn
                })
                .map_err(move |e| {
                    bootstrap_cache2.remove(&PeerInfo::new(addr, their_pk));
                    let _ = bootstrap_cache2
                        .commit()
                        .map_err(|e| error!("Failed to commit bootstrap cache: {}", e));
                    e
                })
        })
        .collect::<Vec<_>>();
    stream::futures_unordered(connections)
        .map_err(SingleConnectionError::Io)
        .into_boxed()
}

fn handshake_incoming_connections<UID: Uid>(
    our_connect_request: ConnectRequest<UID>,
    conn_rx: UnboundedReceiver<ConnectMessage<UID>>,
    their_id: UID,
    our_sk: SecretKey,
) -> BoxStream<(Socket<HandshakeMessage<UID>>, UID), SingleConnectionError> {
    conn_rx
        .map_err(|()| unreachable!())
        .infallible::<SingleConnectionError>()
        .and_then(move |(mut socket, connect_request)| {
            validate_connect_request(their_id, our_connect_request.name_hash, &connect_request)?;
            socket.use_crypto_ctx(CryptoContext::authenticated(
                connect_request.peer_pk,
                our_sk.clone(),
            ));
            Ok({
                socket
                    .send((0, HandshakeMessage::Connect(our_connect_request.clone())))
                    .map_err(SingleConnectionError::Socket)
                    .map(move |socket| (socket, their_id))
            })
        })
        .and_then(|f| f)
        .into_boxed()
}

/// Executes handshake process for the given connections.
fn handshake_outgoing_connections<UID: Uid, S>(
    connections: S,
    our_connect_request: ConnectRequest<UID>,
    their_id: UID,
    their_pk: PublicKey,
    our_sk: SecretKey,
) -> BoxStream<(Socket<HandshakeMessage<UID>>, UID), SingleConnectionError>
where
    S: Stream<Item = Socket<HandshakeMessage<UID>>, Error = SingleConnectionError> + 'static,
{
    let our_name_hash = our_connect_request.name_hash;
    connections
        .and_then(move |socket| {
            socket
                .send((0, HandshakeMessage::Connect(our_connect_request.clone())))
                .map_err(SingleConnectionError::Socket)
        })
        .and_then(move |mut socket| {
            socket.use_crypto_ctx(CryptoContext::authenticated(their_pk, our_sk.clone()));
            socket
                .into_future()
                .map_err(|(err, _socket)| SingleConnectionError::Socket(err))
        })
        .and_then(move |(msg_opt, socket)| match msg_opt {
            None => Err(SingleConnectionError::ConnectionDropped),
            Some(HandshakeMessage::Connect(connect_request)) => {
                validate_connect_request(their_id, our_name_hash, &connect_request)?;
                Ok((socket, connect_request.peer_uid))
            }
            Some(_msg) => Err(SingleConnectionError::UnexpectedMessage),
        })
        .into_boxed()
}

/// Sends connection info to "rendezvous connect" task and waits for connection.
///
/// If given p2p connection info is `None`, returns empty future.
fn connect_p2p(
    our_conn_info: Option<P2pConnectionInfo>,
    their_conn_info: Option<Vec<u8>>,
) -> BoxFuture<PaStream, SingleConnectionError> {
    match (our_conn_info, their_conn_info) {
        (Some(our_conn_info), Some(their_conn_info)) => {
            let conn_rx = our_conn_info.connection_rx;
            let raw_info = Bytes::from(their_conn_info);
            our_conn_info
                .rendezvous_channel
                .send(raw_info)
                .map_err(|_| SingleConnectionError::DeadChannel)
                .and_then(move |_chann| {
                    conn_rx
                        .map_err(|_| SingleConnectionError::DeadChannel)
                        .and_then(|res| res.map_err(SingleConnectionError::RendezvousConnect))
                })
                .into_boxed()
        }
        _ => future::empty().into_boxed(),
    }
}

fn validate_connect_request<UID: Uid>(
    expected_uid: UID,
    our_name_hash: NameHash,
    connect_request: &ConnectRequest<UID>,
) -> Result<(), SingleConnectionError> {
    let &ConnectRequest {
        peer_uid: their_uid,
        name_hash: their_name_hash,
        ..
    } = connect_request;
    if their_uid != expected_uid {
        return Err(SingleConnectionError::InvalidUid(
            format!("{}", their_uid),
            format!("{}", expected_uid),
        ));
    }
    if our_name_hash != their_name_hash {
        return Err(SingleConnectionError::InvalidNameHash(their_name_hash));
    }
    Ok(())
}

/// Spawns p2p rendezvous connect task on the specified event loop.
///
/// Gets peer info from rendezvous relay channel and sends connected tcp stream to connection
/// receiver.
///
/// # Returns
///
/// connection receiver
pub fn start_rendezvous_connect(
    handle: &Handle,
    config: &ConfigFile,
    rendezvous_relay: UnboundedBiChannel<Bytes>,
    p2p: &P2p,
) -> oneshot::Receiver<Result<PaStream, RendezvousConnectError>> {
    let (conn_tx, conn_rx) = oneshot::channel();
    let connect = {
        PaStream::rendezvous_connect(rendezvous_relay, handle, config, p2p)
            .then(move |result| conn_tx.send(result))
            .or_else(|_send_error| Ok(()))
    };

    handle.spawn(connect);
    conn_rx
}

#[cfg(test)]
mod tests {
    use super::*;
    pub use tokio_core::reactor::Core;

    mod connect_p2p {
        use super::*;
        use future_utils::bi_channel::unbounded;

        #[test]
        fn it_returns_empty_future_when_our_connection_info_is_none() {
            let their_conn_info = Some(vec![1, 2, 3]);

            let mut fut = connect_p2p(None, their_conn_info);
            let res = fut.poll();

            let future_is_ready = match unwrap!(res) {
                Async::Ready(_) => true,
                Async::NotReady => false,
            };
            assert!(!future_is_ready);
        }

        #[test]
        fn it_returns_empty_future_when_their_connection_info_is_none() {
            let (rendezvous_channel, _) = unbounded();
            let (_, connection_rx) = oneshot::channel();
            let our_conn_info = Some(P2pConnectionInfo {
                our_info: Bytes::from(vec![]),
                rendezvous_channel,
                connection_rx,
            });

            let mut fut = connect_p2p(our_conn_info, None);
            let res = fut.poll();

            let future_is_ready = match unwrap!(res) {
                Async::Ready(_) => true,
                Async::NotReady => false,
            };
            assert!(!future_is_ready);
        }

        #[test]
        fn it_sends_serialized_p2p_connection_info_to_the_given_channel() {
            let mut core = unwrap!(Core::new());

            let (rendezvous_channel, info_rx) = unbounded();
            let (_, connection_rx) = oneshot::channel();
            let our_conn_info = Some(P2pConnectionInfo {
                our_info: Bytes::from(vec![]),
                rendezvous_channel,
                connection_rx,
            });
            let their_conn_info = Some(vec![1, 2, 3, 4]);

            let fut = connect_p2p(our_conn_info, their_conn_info);
            core.handle().spawn(fut.then(|_| Ok(())));

            let received_conn_info =
                unwrap!(core.run(info_rx.into_future().and_then(|(info, _stream)| Ok(info),)));

            assert_eq!(received_conn_info, Some(Bytes::from(vec![1, 2, 3, 4])));
        }

        #[test]
        fn it_returns_dead_channel_error_if_connection_transmitter_is_dropped() {
            let mut core = unwrap!(Core::new());

            let (rendezvous_channel, _) = unbounded();
            let (conn_tx, connection_rx) = oneshot::channel();
            let our_conn_info = Some(P2pConnectionInfo {
                our_info: Bytes::from(vec![]),
                rendezvous_channel,
                connection_rx,
            });
            let their_conn_info = Some(vec![1, 2, 3, 4]);

            let fut = connect_p2p(our_conn_info, their_conn_info);
            drop(conn_tx);

            let result = core.run(fut);
            let channel_is_dead = match result {
                Err(e) => match e {
                    SingleConnectionError::DeadChannel => true,
                    _ => false,
                },
                _ => false,
            };
            assert!(channel_is_dead);
        }
    }
}
