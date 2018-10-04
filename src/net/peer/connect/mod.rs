// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

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
mod choose;
mod connection_info;
mod demux;
mod ext_reachability;
mod handshake_message;

use self::choose::ChooseOneConnection;
use self::demux::ConnectMessage;
use self::handshake_message::{ConnectRequest, HandshakeMessage};
use config::PeerInfo;
use future_utils::bi_channel::UnboundedBiChannel;
use future_utils::mpsc::UnboundedReceiver;
use futures::sync::mpsc::{self, SendError};
#[cfg(feature = "connections_info")]
use futures::sync::oneshot;
#[cfg(feature = "connections_info")]
use net::peer;
use p2p::P2p;
use priv_prelude::*;
#[cfg(feature = "connections_info")]
use std::time::{Duration, Instant};
#[cfg(feature = "connections_info")]
use util::ConsumedStream;

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
    /// When Crust attempts connection it makes multiple attempts in parallel. This error holds
    /// information of a single attempt failure.
    pub enum SingleConnectionError {
        /// OS error while doing/accepting connection.
        Io(e: io::Error) {
            display("io error initiating/accepting connection: {}", e)
            cause(e)
            from()
        }
        /// Connection, when remote peer has directly accessible listeners, failed.
        DirectConnect(e: DirectConnectError) {
            display("direct connection attempt failed: {}", e)
            cause(e)
        }
        /// Failure to send data over the connection socket.
        Write(e: PaStreamWriteError) {
            display("error writing to underlying stream: {}", e)
            cause(e)
        }
        /// Failure to read data from the connection socket.
        Read(e: PaStreamReadError) {
            display("error reading from underlying stream: {}", e)
            cause(e)
        }
        /// Failure to deserialize message received from remote peer.
        Deserialise(e: SerialisationError) {
            display("error deserilising message from remote peer: {}", e)
            cause(e)
        }
        /// Connection was dropped by remote peer.
        ConnectionDropped {
            display("the connection was dropped by the remote peer")
        }
        /// Attempted to connect to peer that was on a different networ.
        InvalidNameHash(name_hash: NameHash) {
            display("Peer is from a different network. Invalid name hash == {:?}", name_hash)
        }
        /// Remote peer sent us an unexpected message.
        UnexpectedMessage {
            display("Peer sent us an unexpected message variant")
        }
        /// Internal in-memory communication channel died.
        DeadChannel {
            display("Communication channel was cancelled")
        }
        /// Hole punched connection failed.
        RendezvousConnect(e: RendezvousConnectError) {
            display("rendezvous connect failed: {}", e)
            cause(e)
        }
        /// You provided connection info that directs to ourselves.
        RequestedConnectToSelf {
            display("requested a connection to ourselves")
        }
        /// Remote peer we're trying to connect to is no whitelisted.
        NotWhitelisted(ip: IpAddr) {
            display("peer {} is not whitelisted", ip)
        }
        #[cfg(feature = "connections_info")]
        /// Connection timed out.
        Timeout {
            display("Connection timed out")
        }
    }
}

/// Single connection result.
#[cfg(feature = "connections_info")]
#[derive(Debug)]
pub struct ConnectionResult {
    /// Was connection successful? If `result.is_ok()`, then yes. Otherwise it holds an error
    /// that happened during connection.
    pub result: Result<Peer, SingleConnectionError>,
    /// True if connection was direct, false if this is a hole punched connection.
    pub is_direct: bool,
    /// How long connection took.
    pub duration: Duration,
    /// Our public address, if one was detected say during rendezvous connection.
    pub our_addr: Option<PaAddr>,
    /// Remote peer's public address.
    pub their_addr: Option<PaAddr>,
}

/// Try to connect to a peer using all possible means and return a stream of results.
#[cfg(feature = "connections_info")]
pub fn connect_all<C>(
    handle: &Handle,
    name_hash: NameHash,
    mut our_conn_info: PrivConnectionInfo,
    conn_info_rx: C,
    config: &ConfigFile,
    peer_rx: UnboundedReceiver<ConnectMessage>,
    bootstrap_cache: &BootstrapCache,
) -> BoxStream<ConnectionResult, SingleConnectionError>
where
    C: Stream<Item = PubConnectionInfo>,
    C: 'static,
{
    let config = config.clone();
    let handle1 = handle.clone();
    let handle2 = handle.clone();
    let bootstrap_cache = bootstrap_cache.clone();

    let (conns_done_tx, conns_done_rx) = oneshot::channel();

    let mut our_connect_request1 = ConnectRequest {
        connection_id: 0,
        client_uid: our_conn_info.our_uid,
        name_hash,
    };
    let our_connect_request2 = our_connect_request1.clone();

    let all_outgoing_connections = get_their_info(conn_info_rx, our_conn_info.our_uid, &config)
        .and_then(move |their_conn_info| {
            let their_uid = their_conn_info.uid;
            let connection_started = Instant::now();
            let handle2 = handle1.clone();
            our_connect_request1.connection_id = their_conn_info.connection_id;

            let direct_conns = try_connect_directly(
                &handle1,
                their_conn_info.for_direct,
                their_conn_info.pub_key,
                &config,
                &bootstrap_cache,
            );
            let direct_conns = handshake_outgoing_conn_attempts(direct_conns, our_connect_request1)
                .map(move |result| match result {
                    Ok((stream, their_uid)) => ConnectionResult {
                        our_addr: stream.our_public_addr(),
                        their_addr: stream.peer_addr().ok(),
                        result: Ok(peer::from_handshaken_stream(
                            &handle1,
                            their_uid,
                            stream,
                            CrustUser::Node,
                        )),
                        is_direct: true,
                        duration: Instant::now().duration_since(connection_started),
                    },
                    Err(e) => ConnectionResult {
                        result: Err(e),
                        is_direct: true,
                        duration: Instant::now().duration_since(connection_started),
                        our_addr: None, // TODO(povilas): do best to determine our public address
                        their_addr: None, // TODO(povilas): get their addr
                    },
                }).infallible::<SingleConnectionError>();

            let our_p2p_conn_info = our_conn_info.p2p_conn_info.take();
            let rendezvous_conns = try_connect_p2p(
                our_p2p_conn_info,
                their_conn_info.p2p_conn_info,
            ).map(move |result| match result {
                Ok(stream) => ConnectionResult {
                    our_addr: stream.our_public_addr(),
                    their_addr: stream.peer_addr().ok(),
                    result: Ok(peer::from_handshaken_stream(
                        &handle2,
                        their_uid,
                        stream,
                        CrustUser::Node,
                    )),
                    is_direct: false,
                    duration: Instant::now().duration_since(connection_started),
                },
                Err(e) => ConnectionResult {
                    result: Err(e),
                    is_direct: false,
                    duration: Instant::now().duration_since(connection_started),
                    our_addr: None, // TODO(povilas): do best to determine our public address
                    their_addr: None, // TODO(povilas): get their addr
                },
            });
            future::ok(direct_conns.select(rendezvous_conns))
        }).flatten_stream()
        .when_consumed(|| {
            let _ = conns_done_tx.send(());
        });

    let connection_started = Instant::now();
    let direct_incoming = handshake_incoming_connections(our_connect_request2, peer_rx)
        .map_err(|e| panic!("Incoming conn failed: {}", e)) // TODO(povilas): just log an error
        .infallible()
        .map(move |(stream, their_uid)| ConnectionResult {
            our_addr: None, // TODO(povilas): how can we determine public address remote peer connected to us?
            their_addr: stream.peer_addr().ok(),
            result: Ok(peer::from_handshaken_stream(&handle2, their_uid, stream, CrustUser::Node)),
            is_direct: true,
            duration: Instant::now().duration_since(connection_started),
        }).until(conns_done_rx.map_err(|_e| SingleConnectionError::DeadChannel));

    all_outgoing_connections
        .select(direct_incoming)
        .into_boxed()
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
        client_uid: our_info.our_uid,
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
        }).and_then(move |peer| {
            let ip = peer.ip().map_err(ConnectError::Peer)?;
            if config.is_peer_whitelisted(ip, CrustUser::Node) {
                Ok(peer)
            } else {
                Err(ConnectError::NotWhitelisted(ip))
            }
        }).into_boxed()
}

fn get_conn_info_and_connect<C>(
    handle: &Handle,
    conn_info_rx: C,
    our_info: &mut PrivConnectionInfo,
    our_connect_request: &ConnectRequest,
    config: &ConfigFile,
    bootstrap_cache: &BootstrapCache,
) -> BoxStream<(PaStream, PublicEncryptKey), SingleConnectionError>
where
    C: Stream<Item = PubConnectionInfo>,
    C: 'static,
{
    let our_p2p_conn_info = our_info.p2p_conn_info.take();
    let mut our_connect_request = our_connect_request.clone();
    let config = config.clone();
    let handle = handle.clone();
    let bootstrap_cache = bootstrap_cache.clone();

    // We'll retain semantics and take only first connection info for now.
    // Also, note that we can't clone our_p2p_conn_info.
    get_their_info(conn_info_rx, our_info.our_uid, &config)
        .and_then(move |their_info| {
            our_connect_request.connection_id = their_info.connection_id;
            future::ok(attempt_to_connect(
                &handle,
                &config,
                &our_connect_request,
                our_p2p_conn_info,
                their_info,
                &bootstrap_cache,
            ))
        }).flatten_stream()
        .into_boxed()
}

/// Waits for remote peer's connection info on a given channel. Once we receive the info, we
/// validate it.
fn get_their_info<C>(
    conn_info_rx: C,
    our_uid: PublicEncryptKey,
    config: &ConfigFile,
) -> BoxFuture<PubConnectionInfo, SingleConnectionError>
where
    C: Stream<Item = PubConnectionInfo>,
    C: 'static,
{
    let config = config.clone();
    conn_info_rx
        .into_future()
        .map_err(|_e| SingleConnectionError::DeadChannel)
        .and_then(|(their_info_opt, _conn_info_rx)| {
            their_info_opt.ok_or(SingleConnectionError::DeadChannel)
        }).and_then(move |their_info| {
            validate_their_conn_info(&their_info, &our_uid, &config).map(move |()| their_info)
        }).into_boxed()
}

fn validate_their_conn_info(
    their_info: &PubConnectionInfo,
    our_uid: &PublicEncryptKey,
    config: &ConfigFile,
) -> Result<(), SingleConnectionError> {
    if *our_uid == their_info.uid {
        return Err(SingleConnectionError::RequestedConnectToSelf);
    }
    for addr in &their_info.for_direct {
        if !config.is_peer_whitelisted(addr.ip(), CrustUser::Node) {
            return Err(SingleConnectionError::NotWhitelisted(addr.ip()));
        }
    }

    Ok(())
}

/// Initiates both direct and p2p connections.
fn attempt_to_connect(
    handle: &Handle,
    config: &ConfigFile,
    our_connect_request: &ConnectRequest,
    our_p2p_conn_info: Option<P2pConnectionInfo>,
    their_info: PubConnectionInfo,
    bootstrap_cache: &BootstrapCache,
) -> BoxStream<(PaStream, PublicEncryptKey), SingleConnectionError> {
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
        direct_connections.select(rendezvous_conn).into_boxed()
    };
    handshake_outgoing_connections(all_connections, our_connect_request.clone())
}

/// Spawns a background task that gracefully shuts down all not chosen connections.
fn finalize_connections(handle: &Handle, conns: BoxStream<PaStream, SingleConnectionError>) {
    let task = conns
        .for_each(|stream| stream.finalize().map_err(SingleConnectionError::Io))
        .log_error(
            LogLevel::Info,
            "Failed to gracefully shutdown unused socket",
        ).then(|_| Ok(()));
    handle.spawn(task);
}

// TODO(povilas): replace this with try_connect_directly(), otherwise single
// error will terminate the connection stream.
fn connect_directly(
    evloop_handle: &Handle,
    addrs: Vec<PaAddr>,
    their_pk: PublicEncryptKey,
    config: &ConfigFile,
    bootstrap_cache: &BootstrapCache,
) -> BoxStream<PaStream, SingleConnectionError> {
    let bootstrap_cache = bootstrap_cache.clone();
    let connections = addrs
        .into_iter()
        .map(move |addr| {
            let bootstrap_cache1 = bootstrap_cache.clone();
            let bootstrap_cache2 = bootstrap_cache.clone();
            let their_pk0 = their_pk;
            let their_pk1 = their_pk;
            let their_pk2 = their_pk;
            PaStream::direct_connect(evloop_handle, &addr, their_pk0, config)
                .map(move |conn| {
                    bootstrap_cache1.put(&PeerInfo::new(addr, their_pk1));
                    let _ = bootstrap_cache1
                        .commit()
                        .map_err(|e| error!("Failed to commit bootstrap cache: {}", e));
                    conn
                }).map_err(move |e| {
                    bootstrap_cache2.remove(&PeerInfo::new(addr, their_pk2));
                    let _ = bootstrap_cache2
                        .commit()
                        .map_err(|e| error!("Failed to commit bootstrap cache: {}", e));
                    e
                })
        }).collect::<Vec<_>>();
    stream::futures_unordered(connections)
        .map_err(SingleConnectionError::DirectConnect)
        .into_boxed()
}

// TODO(povilas): make connect_directly() a wrapper of this method where it checks each result
// and unwraps error if it's present?
/// Tries multiple direct connections to given addresses.
/// This function never fails, rather it collects results for all connections.
#[cfg(feature = "connections_info")]
fn try_connect_directly(
    handle: &Handle,
    addrs: Vec<PaAddr>,
    their_pk: PublicEncryptKey,
    config: &ConfigFile,
    bootstrap_cache: &BootstrapCache,
) -> BoxStream<Result<PaStream, SingleConnectionError>, Void> {
    let bootstrap_cache = bootstrap_cache.clone();
    let connections = addrs
        .into_iter()
        .map(move |addr| {
            let bootstrap_cache1 = bootstrap_cache.clone();
            let bootstrap_cache2 = bootstrap_cache.clone();
            let their_pk0 = their_pk;
            let their_pk1 = their_pk;
            let their_pk2 = their_pk;
            PaStream::direct_connect(handle, &addr, their_pk0, config)
                .map_err(SingleConnectionError::DirectConnect)
                .with_timeout(Duration::from_secs(CONNECTIONS_TIMEOUT), &handle)
                .and_then(|res| res.ok_or(SingleConnectionError::Timeout))
                .then(move |result| match result {
                    Ok(conn) => {
                        bootstrap_cache1.put(&PeerInfo::new(addr, their_pk1));
                        let _ = bootstrap_cache1
                            .commit()
                            .map_err(|e| error!("Failed to commit bootstrap cache: {}", e));
                        Ok(Ok(conn))
                    }
                    Err(e) => {
                        bootstrap_cache2.remove(&PeerInfo::new(addr, their_pk2));
                        let _ = bootstrap_cache2
                            .commit()
                            .map_err(|e| error!("Failed to commit bootstrap cache: {}", e));
                        Ok(Err(e))
                    }
                })
        }).collect::<Vec<_>>();
    stream::futures_unordered(connections).into_boxed()
}

// TODO(povilas): shouldn't this function be infallible?
// Say one incoming connection fails, that shouldn't affect other connections.
// Probably just log an error instead of terminating the stream.
fn handshake_incoming_connections(
    mut our_connect_request: ConnectRequest,
    conn_rx: UnboundedReceiver<ConnectMessage>,
) -> BoxStream<(PaStream, PublicEncryptKey), SingleConnectionError> {
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
        }).and_then(|f| f)
        .into_boxed()
}

/// Executes handshake process for the given connections.
fn handshake_outgoing_connections<S>(
    connections: S,
    our_connect_request: ConnectRequest,
) -> BoxStream<(PaStream, PublicEncryptKey), SingleConnectionError>
where
    S: Stream<Item = PaStream, Error = SingleConnectionError> + 'static,
{
    let our_name_hash = our_connect_request.name_hash;
    connections
        .and_then(move |stream| {
            stream
                .send_serialized(HandshakeMessage::Connect(our_connect_request.clone()))
                .map_err(SingleConnectionError::Write)
        }).and_then(move |stream| {
            stream
                .recv_serialized()
                .map_err(SingleConnectionError::Read)
        }).and_then(move |(msg_opt, stream)| match msg_opt {
            None => Err(SingleConnectionError::ConnectionDropped),
            Some(HandshakeMessage::Connect(connect_request)) => {
                validate_connect_request(our_name_hash, &connect_request)?;
                Ok((stream, connect_request.client_uid))
            }
            Some(_msg) => Err(SingleConnectionError::UnexpectedMessage),
        }).into_boxed()
}

/// Executes handshake process for the given connections.
#[cfg(feature = "connections_info")]
fn handshake_outgoing_conn_attempts<S>(
    connections: S,
    our_connect_request: ConnectRequest,
) -> BoxStream<Result<(PaStream, PublicEncryptKey), SingleConnectionError>, Void>
where
    S: Stream<Item = Result<PaStream, SingleConnectionError>, Error = Void> + 'static,
{
    let our_name_hash = our_connect_request.name_hash;
    connections
        .and_then(move |conn_attempt| match conn_attempt {
            Err(e) => future::ok(Err(e)).into_boxed(),
            Ok(stream) => stream
                .send_serialized(HandshakeMessage::Connect(our_connect_request.clone()))
                .map_err(SingleConnectionError::Write)
                .and_then(move |stream| {
                    stream
                        .recv_serialized()
                        .map_err(SingleConnectionError::Read)
                }).and_then(move |(msg_opt, stream)| match msg_opt {
                    None => Err(SingleConnectionError::ConnectionDropped),
                    Some(HandshakeMessage::Connect(connect_request)) => {
                        validate_connect_request(our_name_hash, &connect_request)?;
                        Ok((stream, connect_request.client_uid))
                    }
                    Some(_msg) => Err(SingleConnectionError::UnexpectedMessage),
                }).then(Ok)
                .into_boxed(),
        }).into_boxed()
}

/// Sends connection info to "rendezvous connect" task and waits for connection.
///
/// If given p2p connection info is `None`, returns empty future.
fn connect_p2p(
    our_conn_info: Option<P2pConnectionInfo>,
    their_conn_info: Option<Vec<u8>>,
) -> BoxStream<PaStream, SingleConnectionError> {
    match (our_conn_info, their_conn_info) {
        (Some(our_conn_info), Some(their_conn_info)) => {
            let conn_rx = our_conn_info.connection_rx;
            let raw_info = Bytes::from(their_conn_info);
            our_conn_info
                .rendezvous_channel
                .send(raw_info)
                .map_err(|_| SingleConnectionError::DeadChannel)
                .and_then(move |_chann| {
                    future::ok(
                        conn_rx
                        .map_err(|_| SingleConnectionError::DeadChannel)
                        // NOTE: and_then is called twice intentionally because conn_rx receives
                        // a result that has another result wrapped in it.
                        .and_then(|res| res.map_err(SingleConnectionError::RendezvousConnect))
                        .and_then(|res| res.map_err(SingleConnectionError::RendezvousConnect)),
                    )
                }).flatten_stream()
                .into_boxed()
        }
        _ => stream::empty().into_boxed(),
    }
}

#[cfg(feature = "connections_info")]
fn try_connect_p2p(
    our_conn_info: Option<P2pConnectionInfo>,
    their_conn_info: Option<Vec<u8>>,
) -> BoxStream<Result<PaStream, SingleConnectionError>, SingleConnectionError> {
    match (our_conn_info, their_conn_info) {
        (Some(our_conn_info), Some(their_conn_info)) => {
            let conn_rx = our_conn_info.connection_rx;
            let raw_info = Bytes::from(their_conn_info);
            our_conn_info
                .rendezvous_channel
                .send(raw_info)
                .map_err(|_| SingleConnectionError::DeadChannel)
                .and_then(move |_chann| {
                    future::ok(
                        conn_rx
                            .map_err(|_| SingleConnectionError::DeadChannel)
                            .and_then(|res| {
                                res.map_err(SingleConnectionError::RendezvousConnect)
                                    .map(|res| {
                                        res.map_err(SingleConnectionError::RendezvousConnect)
                                    })
                            }),
                    )
                }).flatten_stream()
                .into_boxed()
        }
        _ => stream::empty().into_boxed(),
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
) -> mpsc::Receiver<Result<Result<PaStream, RendezvousConnectError>, RendezvousConnectError>> {
    let (conn_tx, conn_rx) = mpsc::channel(8);
    let connect = {
        PaStream::rendezvous_connect(rendezvous_relay, handle, config, p2p)
            .then(move |result| conn_tx.clone().send(result).then(|_| Ok(())))
            .for_each(|_| Ok(()))
    };

    handle.spawn(connect);
    conn_rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::sync::mpsc;
    use tokio_core::reactor::Core;

    mod connect_p2p {
        use super::*;
        use future_utils::bi_channel::unbounded;

        #[test]
        fn it_returns_empty_stream_when_our_connection_info_is_none() {
            let their_conn_info = Some(vec![1, 2, 3]);

            let mut stream = connect_p2p(None, their_conn_info);
            let res = stream.poll();

            let stream_is_consumed = match unwrap!(res) {
                Async::Ready(None) => true,
                _ => false,
            };
            assert!(stream_is_consumed);
        }

        #[test]
        fn it_returns_empty_future_when_their_connection_info_is_none() {
            let (rendezvous_channel, _) = unbounded();
            let (_, connection_rx) = mpsc::channel(8);
            let our_conn_info = Some(P2pConnectionInfo {
                our_info: Bytes::from(vec![]),
                rendezvous_channel,
                connection_rx,
            });

            let mut stream = connect_p2p(our_conn_info, None);
            let res = stream.poll();

            let stream_is_consumed = match unwrap!(res) {
                Async::Ready(_) => true,
                _ => false,
            };
            assert!(stream_is_consumed);
        }

        #[test]
        fn it_sends_serialized_p2p_connection_info_to_the_given_channel() {
            let mut core = unwrap!(Core::new());

            let (rendezvous_channel, info_rx) = unbounded();
            let (_, connection_rx) = mpsc::channel(8);
            let our_conn_info = Some(P2pConnectionInfo {
                our_info: Bytes::from(vec![]),
                rendezvous_channel,
                connection_rx,
            });
            let their_conn_info = Some(vec![1, 2, 3, 4]);

            let stream = connect_p2p(our_conn_info, their_conn_info);
            core.handle()
                .spawn(stream.for_each(|_| Ok(())).then(|_| Ok(())));

            let received_conn_info =
                unwrap!(core.run(info_rx.into_future().and_then(|(info, _stream)| Ok(info),)));

            assert_eq!(received_conn_info, Some(Bytes::from(vec![1, 2, 3, 4])));
        }

        #[test]
        fn it_returns_dead_channel_error_if_connection_transmitter_is_dropped() {
            let mut core = unwrap!(Core::new());

            let (rendezvous_channel, _) = unbounded();
            let (conn_tx, connection_rx) = mpsc::channel(8);
            let our_conn_info = Some(P2pConnectionInfo {
                our_info: Bytes::from(vec![]),
                rendezvous_channel,
                connection_rx,
            });
            let their_conn_info = Some(vec![1, 2, 3, 4]);

            let stream = connect_p2p(our_conn_info, their_conn_info).for_each(|_| Ok(()));
            drop(conn_tx);

            let result = core.run(stream);
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
