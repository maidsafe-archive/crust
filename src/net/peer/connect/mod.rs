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
use futures::sync::mpsc::SendError;
use futures::sync::oneshot;
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
    let our_uid = our_info.our_uid;
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
        }).and_then(move |their_info| {
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
        }).flatten_stream()
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
        direct_connections
            .select(rendezvous_conn.into_stream())
            .into_boxed()
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
                }).into_boxed()
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
}
