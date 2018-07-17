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

pub use self::bootstrap::{
    bootstrap, BootstrapError, Cache as BootstrapCache, CacheError as BootstrapCacheError,
    ConnectHandshakeError,
};
pub use self::bootstrap_acceptor::{BootstrapAcceptError, BootstrapAcceptor};
pub use self::connection_info::{P2pConnectionInfo, PrivConnectionInfo, PubConnectionInfo};
pub use self::demux::Demux;
pub use self::ext_reachability::ExternalReachability;
pub use self::handshake_message::{BootstrapDenyReason, BootstrapRequest};

mod bootstrap;
mod bootstrap_acceptor;
mod connection_info;
mod demux;
mod ext_reachability;
mod handshake_message;

use config::PeerInfo;
use future_utils::bi_channel::UnboundedBiChannel;
use future_utils::mpsc::UnboundedReceiver;
use futures::sync::mpsc::SendError;
use futures::sync::oneshot;
use net::peer;
use net::peer::connect::demux::ConnectMessage;
use net::peer::connect::handshake_message::{ConnectRequest, HandshakeMessage};
use p2p::P2p;
use priv_prelude::*;

pub type RendezvousConnectError = PaRendezvousConnectError<Void, SendError<Bytes>>;

// Seconds after which all connections will timeout.
pub const CONNECTIONS_TIMEOUT: u64 = 60;

quick_error! {
    #[derive(Debug)]
    pub enum ConnectError {
        AllConnectionsFailed(v: Vec<SingleConnectionError>) {
            description("all attempts to connect to the remote peer failed")
            display("all {} attempts to connect to the remote peer failed: {:?}", v.len(), v)
        }
        Peer(e: PeerError) {
            description("error on Peer object")
            display("error on Peer object: {}", e)
        }
        NotWhitelisted(ip: IpAddr) {
            description("peer is not whitelisted")
            display("peer {} is not whitelisted", ip)
        }
        ExchangeConnectionInfo {
            description("Failed to exchange connection info")
        }
        Serialisation(e: SerialisationError) {
            description("error serialising message for remote peer")
            display("error serialising message for remote peer: {}", e)
            cause(e)
            from()
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
        DirectConnect(e: DirectConnectError) {
            description("direct connection attempt failed")
            display("direct connection attempt failed: {}", e)
            cause(e)
        }
        Write(e: PaStreamWriteError) {
            description("error writing to underlying stream")
            display("error writing to underlying stream: {}", e)
            cause(e)
        }
        Read(e: PaStreamReadError) {
            description("error reading from underlying stream")
            display("error reading from underlying stream: {}", e)
            cause(e)
        }
        Deserialise(e: SerialisationError) {
            description("error deserilising message from remote peer")
            display("error deserilising message from remote peer: {}", e)
            cause(e)
        }
        ConnectionDropped {
            description("the connection was dropped by the remote peer")
        }
        InvalidNameHash(name_hash: NameHash) {
            description("Peer is from a different network")
            display("Peer is from a different network. Invalid name hash == {:?}", name_hash)
        }
        UnexpectedMessage {
            description("Peer sent us an unexpected message variant")
        }
        DeadChannel {
            description("Communication channel was cancelled")
        }
        RendezvousConnect(e: RendezvousConnectError) {
            description("rendezvous connect failed")
            display("rendezvous connect failed: {}", e)
            cause(e)
        }
        RequestedConnectToSelf {
            description("requested a connection to ourselves")
        }
        NotWhitelisted(ip: IpAddr) {
            description("peer is not whitelisted")
            display("peer {} is not whitelisted", ip)
        }
    }
}

/// Perform a rendezvous connect to a peer. Both peers call this simultaneously using
/// `PubConnectionInfo` they received from the other peer out-of-band.
pub fn connect<C>(
    handle: &Handle,
    name_hash: NameHash,
    mut our_info: PrivConnectionInfo,
    conn_info_rx: C,
    config: &ConfigFile,
    peer_rx: UnboundedReceiver<ConnectMessage>,
    bootstrap_cache: &BootstrapCache,
) -> BoxFuture<Peer, ConnectError>
where
    C: Stream<Item = PubConnectionInfo>,
    C: 'static,
{
    let our_connect_request1 = ConnectRequest {
        connection_id: 0,
        client_uid: our_info.our_uid.clone(),
        name_hash,
    };
    let all_outgoing_connections = get_conn_info_and_connect(
        handle,
        conn_info_rx,
        &mut our_info,
        &our_connect_request1,
        config,
        bootstrap_cache,
    );
    let direct_incoming = handshake_incoming_connections(our_connect_request1, peer_rx);
    let all_connections = all_outgoing_connections
        .select(direct_incoming)
        .with_timeout(Duration::from_secs(CONNECTIONS_TIMEOUT), handle);

    let config = config.clone();
    let handle = handle.clone();
    ChooseOneConnection::new(&handle, all_connections, our_info.our_uid)
        .map(move |(peer, other_conns)| {
            finalize_connections(&handle, other_conns);
            peer
        })
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

fn get_conn_info_and_connect<C>(
    handle: &Handle,
    conn_info_rx: C,
    our_info: &mut PrivConnectionInfo,
    our_connect_request: &ConnectRequest,
    config: &ConfigFile,
    bootstrap_cache: &BootstrapCache,
) -> BoxStream<(PaStream, PublicId), SingleConnectionError>
where
    C: Stream<Item = PubConnectionInfo>,
    C: 'static,
{
    let our_uid = our_info.our_uid.clone();
    let our_p2p_conn_info = our_info.p2p_conn_info.take();
    let mut our_connect_request = our_connect_request.clone();
    let config = config.clone();
    let handle = handle.clone();
    let bootstrap_cache = bootstrap_cache.clone();

    // We'll retain semantics and take only first connection info for now.
    // Also, note that we can't clone our_p2p_conn_info.
    conn_info_rx
        .into_future()
        .map_err(|_e| SingleConnectionError::DeadChannel)
        .and_then(|(their_info_opt, _conn_info_rx)| {
            their_info_opt.ok_or(SingleConnectionError::DeadChannel)
        })
        .and_then(move |their_info| {
            if our_uid == their_info.uid {
                return future::err(SingleConnectionError::RequestedConnectToSelf);
            }

            for addr in &their_info.for_direct {
                if !config.is_peer_whitelisted(addr.ip(), CrustUser::Node) {
                    return future::err(SingleConnectionError::NotWhitelisted(addr.ip()));
                }
            }

            our_connect_request.connection_id = their_info.connection_id;
            future::ok(attempt_to_connect(
                &handle,
                &config,
                &our_connect_request,
                our_p2p_conn_info,
                their_info,
                &bootstrap_cache,
            ))
        })
        .flatten_stream()
        .into_boxed()
}

/// Initiates both direct and p2p connections.
fn attempt_to_connect(
    handle: &Handle,
    config: &ConfigFile,
    our_connect_request: &ConnectRequest,
    our_p2p_conn_info: Option<P2pConnectionInfo>,
    their_info: PubConnectionInfo,
    bootstrap_cache: &BootstrapCache,
) -> BoxStream<(PaStream, PublicId), SingleConnectionError> {
    let direct_connections = {
        let handle = handle.clone();
        connect_directly(
            &handle,
            their_info.for_direct,
            their_info.pub_key,
            config,
            bootstrap_cache,
        )
    };
    let all_connections = if config.rendezvous_connections_disabled() {
        direct_connections.into_boxed()
    } else {
        let rendezvous_conn = connect_p2p(our_p2p_conn_info, their_info.p2p_conn_info);
        direct_connections
            .select(rendezvous_conn.into_stream())
            .into_boxed()
    };
    handshake_outgoing_connections(all_connections, our_connect_request.clone())
}

/// When "choose connection" message is received, this data is given.
type ChooseConnectionResult = Option<(HandshakeMessage, PaStream, PublicId)>;

/// Future that ensures that both peers select the same connection.
/// Takes all pending handshaken connections and chooses the first one successful.
/// Depending on service id either initiates connection choice message or waits for one.
struct ChooseOneConnection<S>
where
    S: Stream<Item = (PaStream, PublicId), Error = SingleConnectionError> + 'static,
{
    handle: Handle,
    all_connections: Option<S>,
    all_connections_are_done: bool,
    our_uid: PublicId,
    choose_sent: Option<BoxFuture<(PaStream, PublicId), SingleConnectionError>>,
    choose_waiting: Vec<BoxFuture<ChooseConnectionResult, SingleConnectionError>>,
    errors: Vec<SingleConnectionError>,
}

impl<S> ChooseOneConnection<S>
where
    S: Stream<Item = (PaStream, PublicId), Error = SingleConnectionError> + 'static,
{
    fn new(handle: &Handle, connections: S, our_uid: PublicId) -> Self {
        Self {
            handle: handle.clone(),
            all_connections: Some(connections),
            all_connections_are_done: false,
            our_uid,
            choose_sent: None,
            choose_waiting: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Polls all potentially ready connections.
    /// Collects all the errors. If none of connections is ready, returns.
    fn poll_connections(&mut self) -> Result<(), SerialisationError> {
        let mut all_conns = unwrap!(
            self.all_connections.take(),
            "ChooseOneConnection was destroyed",
        );
        while !self.all_connections_are_done {
            match all_conns.poll() {
                Ok(Async::Ready(Some((stream, their_uid)))) => {
                    self.on_conn_ready(stream, their_uid)?
                }
                Ok(Async::Ready(None)) => {
                    self.all_connections_are_done = true;
                    break;
                }
                Ok(Async::NotReady) => break,
                Err(e) => self.errors.push(e),
            }
        }
        // Fighting borrow checker
        self.all_connections = Some(all_conns);
        Ok(())
    }

    fn on_conn_ready(
        &mut self,
        stream: PaStream,
        their_uid: PublicId,
    ) -> Result<(), SerialisationError> {
        if self.our_uid > their_uid {
            self.choose_sent = Some({
                let msg = Bytes::from(serialisation::serialise(
                    &HandshakeMessage::ChooseConnection,
                )?);
                stream
                    .send(msg)
                    .map_err(SingleConnectionError::Write)
                    .map(move |stream| (stream, their_uid))
                    .into_boxed()
            });
            // we'll take first ready connection
            self.all_connections_are_done = true;
        } else {
            self.choose_waiting.push(
                stream
                    .into_future()
                    .map_err(|(err, _socket)| SingleConnectionError::Read(err))
                    .and_then(move |(msg_opt, stream)| match msg_opt {
                        Some(msg) => {
                            let handshake = {
                                serialisation::deserialise(&msg)
                                    .map_err(SingleConnectionError::Deserialise)?
                            };
                            Ok(Some((handshake, stream, their_uid)))
                        }
                        None => Ok(None),
                    })
                    .into_boxed(),
            );
        }
        Ok(())
    }

    fn send_choose(&mut self) -> Result<Option<Peer>, SingleConnectionError> {
        let handle = &self.handle;
        if let Some(mut fut) = self.choose_sent.take() {
            match fut.poll() {
                Ok(Async::Ready((stream, their_uid))) => {
                    return Ok(Some(peer::from_handshaken_stream(
                        handle,
                        their_uid,
                        stream,
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
    fn recv_choose(&mut self) -> Option<Peer> {
        let handle = &self.handle;
        let mut i = 0;
        while i < self.choose_waiting.len() {
            match self.choose_waiting[i].poll() {
                Ok(Async::Ready(Some((HandshakeMessage::ChooseConnection, stream, their_uid)))) => {
                    return Some(peer::from_handshaken_stream(
                        handle,
                        their_uid,
                        stream,
                        CrustUser::Node,
                    ));
                }
                Ok(Async::Ready(Some((_msg, _stream, _their_uid)))) => {
                    self.errors.push(SingleConnectionError::UnexpectedMessage);
                    let _ = self.choose_waiting.swap_remove(i);
                }
                Ok(Async::Ready(None)) => {
                    self.errors.push(SingleConnectionError::ConnectionDropped);
                    let _ = self.choose_waiting.swap_remove(i);
                }
                Ok(Async::NotReady) => i += 1,
                Err(e) => {
                    self.errors.push(e);
                    let _ = self.choose_waiting.swap_remove(i);
                }
            }
        }
        None
    }

    /// Collects all connections that did not finish connection procedure yet.
    fn other_connections(&mut self) -> BoxStream<PaStream, SingleConnectionError> {
        let conns = mem::replace(&mut self.choose_waiting, Vec::new());
        let choose_waiting_conns = {
            stream::iter_ok::<_, SingleConnectionError>(
                conns.into_iter().map(|conn_fut| conn_fut.into_stream()),
            ).flatten()
                .filter_map(|conn_res_opt| {
                    conn_res_opt.map(|(_handshake_msg, stream, _uid)| stream)
                })
        };
        let remaining_conns = unwrap!(self.all_connections.take())
            .map(|(stream, _uid)| stream)
            .chain(choose_waiting_conns);

        if let Some(conn_fut) = self.choose_sent.take() {
            remaining_conns
                .chain(conn_fut.map(|(stream, _uid)| stream).into_stream())
                .into_boxed()
        } else {
            remaining_conns.into_boxed()
        }
    }
}

impl<S> Future for ChooseOneConnection<S>
where
    S: Stream<Item = (PaStream, PublicId), Error = SingleConnectionError> + 'static,
{
    type Item = (Peer, BoxStream<PaStream, SingleConnectionError>);
    type Error = ConnectError;

    /// Yields first successful connection.
    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        self.poll_connections()?;

        match self.send_choose() {
            Ok(Some(peer)) => return Ok(Async::Ready((peer, self.other_connections()))),
            Err(e) => return Err(ConnectError::AllConnectionsFailed(vec![e])),
            Ok(None) => (),
        }
        if let Some(peer) = self.recv_choose() {
            return Ok(Async::Ready((peer, self.other_connections())));
        }

        if self.all_connections_are_done
            && self.choose_sent.is_none()
            && self.choose_waiting.is_empty()
        {
            let errors = mem::replace(&mut self.errors, Vec::new());
            Err(ConnectError::AllConnectionsFailed(errors))
        } else {
            Ok(Async::NotReady)
        }
    }
}

/// Spawns a background task that gracefully shuts down all not chosen connections.
fn finalize_connections(handle: &Handle, conns: BoxStream<PaStream, SingleConnectionError>) {
    let task = conns
        .for_each(|stream| stream.finalize().map_err(SingleConnectionError::Io))
        .log_error(
            LogLevel::Info,
            "Failed to gracefully shutdown unused socket",
        )
        .then(|_| Ok(()));
    handle.spawn(task);
}

fn connect_directly(
    evloop_handle: &Handle,
    addrs: Vec<PaAddr>,
    their_pk: PublicId,
    config: &ConfigFile,
    bootstrap_cache: &BootstrapCache,
) -> BoxStream<PaStream, SingleConnectionError> {
    let bootstrap_cache = bootstrap_cache.clone();
    let connections = addrs
        .into_iter()
        .map(move |addr| {
            let bootstrap_cache1 = bootstrap_cache.clone();
            let bootstrap_cache2 = bootstrap_cache.clone();
            let their_pk0 = their_pk.clone();
            let their_pk1 = their_pk.clone();
            let their_pk2 = their_pk.clone();
            PaStream::direct_connect(evloop_handle, &addr, their_pk0, config)
                .map(move |conn| {
                    bootstrap_cache1.put(&PeerInfo::new(addr, their_pk1));
                    let _ = bootstrap_cache1
                        .commit()
                        .map_err(|e| error!("Failed to commit bootstrap cache: {}", e));
                    conn
                })
                .map_err(move |e| {
                    bootstrap_cache2.remove(&PeerInfo::new(addr, their_pk2));
                    let _ = bootstrap_cache2
                        .commit()
                        .map_err(|e| error!("Failed to commit bootstrap cache: {}", e));
                    e
                })
        })
        .collect::<Vec<_>>();
    stream::futures_unordered(connections)
        .map_err(SingleConnectionError::DirectConnect)
        .into_boxed()
}

fn handshake_incoming_connections(
    mut our_connect_request: ConnectRequest,
    conn_rx: UnboundedReceiver<ConnectMessage>,
) -> BoxStream<(PaStream, PublicId), SingleConnectionError> {
    conn_rx
        .infallible::<SingleConnectionError>()
        .and_then(move |(stream, connect_request)| {
            validate_connect_request(our_connect_request.name_hash, &connect_request)?;
            our_connect_request.connection_id = connect_request.connection_id;
            Ok({
                stream
                    .send_serialized(HandshakeMessage::Connect(our_connect_request.clone()))
                    .map_err(SingleConnectionError::Write)
                    .map(move |stream| (stream, connect_request.client_uid))
            })
        })
        .and_then(|f| f)
        .into_boxed()
}

/// Executes handshake process for the given connections.
fn handshake_outgoing_connections<S>(
    connections: S,
    our_connect_request: ConnectRequest,
) -> BoxStream<(PaStream, PublicId), SingleConnectionError>
where
    S: Stream<Item = PaStream, Error = SingleConnectionError> + 'static,
{
    let our_name_hash = our_connect_request.name_hash;
    connections
        .and_then(move |stream| {
            stream
                .send_serialized(HandshakeMessage::Connect(our_connect_request.clone()))
                .map_err(SingleConnectionError::Write)
        })
        .and_then(move |stream| {
            stream
                .recv_serialized()
                .map_err(SingleConnectionError::Read)
        })
        .and_then(move |(msg_opt, stream)| match msg_opt {
            None => Err(SingleConnectionError::ConnectionDropped),
            Some(HandshakeMessage::Connect(connect_request)) => {
                validate_connect_request(our_name_hash, &connect_request)?;
                Ok((stream, connect_request.client_uid))
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

fn validate_connect_request(
    our_name_hash: NameHash,
    connect_request: &ConnectRequest,
) -> Result<(), SingleConnectionError> {
    let &ConnectRequest {
        name_hash: their_name_hash,
        ..
    } = connect_request;
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

    mod choose_one_connection {
        use super::*;

        fn rand_peer_uid() -> PublicId {
            SecretId::new().public_id().clone()
        }

        mod other_connections {
            use super::*;

            /// Constructs fake connection based on in-memory stream.
            fn fake_connection() -> (PaStream, PublicId) {
                let our_sk = SecretId::new();
                let shared_secret = our_sk.shared_secret(&rand_peer_uid());
                let mem_stream = Framed::new(memstream::EchoStream::default());
                (
                    PaStream::from_framed_mem_stream(mem_stream, shared_secret),
                    rand_peer_uid(),
                )
            }

            #[test]
            fn it_returns_stream_of_all_pending_connections() {
                let mut evloop = unwrap!(Core::new());
                let handle = evloop.handle();

                let conns = stream::iter_ok(vec![fake_connection()]);
                let our_uid = rand_peer_uid();

                let mut choose_conn = ChooseOneConnection::new(&handle, conns, our_uid);
                choose_conn.choose_sent = Some(future::ok(fake_connection()).into_boxed());
                let conn = fake_connection();
                let choose_waiting_conn = (HandshakeMessage::ChooseConnection, conn.0, conn.1);
                choose_conn.choose_waiting =
                    vec![future::ok(Some(choose_waiting_conn)).into_boxed()];

                let other_conns = unwrap!(evloop.run(choose_conn.other_connections().collect()));

                assert_eq!(other_conns.len(), 3);
            }

            #[test]
            fn it_clears_pending_connections() {
                let mut evloop = unwrap!(Core::new());
                let handle = evloop.handle();

                let conns = stream::iter_ok(vec![fake_connection()]);
                let our_uid = rand_peer_uid();

                let mut choose_conn = ChooseOneConnection::new(&handle, conns, our_uid);
                choose_conn.choose_sent = Some(future::ok(fake_connection()).into_boxed());
                let conn = fake_connection();
                let choose_waiting_conn = (HandshakeMessage::ChooseConnection, conn.0, conn.1);
                choose_conn.choose_waiting =
                    vec![future::ok(Some(choose_waiting_conn)).into_boxed()];

                let _ = unwrap!(evloop.run(choose_conn.other_connections().collect()));

                assert!(choose_conn.all_connections.is_none());
                assert!(choose_conn.choose_waiting.is_empty());
                assert!(choose_conn.choose_sent.is_none());
            }
        }
    }
}
