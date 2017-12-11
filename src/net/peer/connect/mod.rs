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

pub use self::bootstrap::{BootstrapError, ConnectHandshakeError, bootstrap};
pub use self::bootstrap_acceptor::{BootstrapAcceptError, BootstrapAcceptor};
pub use self::connection_info::{P2pConnectionInfo, PrivConnectionInfo, PubConnectionInfo};
pub use self::demux::Demux;
pub use self::ext_reachability::ExternalReachability;
pub use self::handshake_message::BootstrapDenyReason;

mod bootstrap;
mod connection_info;
mod ext_reachability;
mod demux;
mod handshake_message;
mod bootstrap_acceptor;

use future_utils::bi_channel::UnboundedBiChannel;
use futures::sync::mpsc::{SendError, UnboundedReceiver};
use futures::sync::oneshot;
use net::peer;
use net::peer::connect::demux::ConnectMessage;
use net::peer::connect::handshake_message::{ConnectRequest, HandshakeMessage};
use priv_prelude::*;
use tokio_io;

/// Every `Crust` request should start with sending this header.
const CRUST_REQ_HEADER: [u8; 8] = [b'C', b'R', b'U', b'S', b'T', 0, 0, 0];

pub type RendezvousConnectError = PaRendezvousConnectError<Void, SendError<Bytes>>;

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
    //_config: ConfigFile,
    peer_rx: UnboundedReceiver<ConnectMessage<UID>>,
) -> BoxFuture<Peer<UID>, ConnectError> {
    if our_info.id == their_info.id {
        return future::result(Err(ConnectError::RequestedConnectToSelf)).into_boxed();
    }

    // TODO(povilas): respect `whitelisted_node_ips` config

    let their_id = their_info.id;
    let our_connect_request = ConnectRequest {
        uid: our_info.id,
        name_hash: name_hash,
    };

    let direct_connections = connect_directly(handle, their_info.for_direct);
    let p2p_connection = connect_p2p(our_info.p2p_conn_info, their_info.p2p_conn_info);
    let all_outgoing_connections = handshake_outgoing_connections(
        handle,
        direct_connections.select(p2p_connection.into_stream()),
        our_connect_request.clone(),
        their_id,
    );

    let direct_incoming = handshake_incoming_connections(our_connect_request, peer_rx, their_id);
    let all_connections = all_outgoing_connections.select(direct_incoming);
    choose_peer(handle, all_connections, our_info.id, their_id)
}

/// Takes all pending handshaken connections and chooses the first one successful.
///
/// Then this connection is wrapped in a `Peer` structure.
/// Depending on service id either initiates connection choice message or waits for one.
fn choose_peer<UID: Uid, S>(
    handle: &Handle,
    all_connections: S,
    our_id: UID,
    their_id: UID,
) -> BoxFuture<Peer<UID>, ConnectError>
where
    S: Stream<Item = (Socket<HandshakeMessage<UID>>, UID), Error = SingleConnectionError> + 'static,
{
    let handle_copy = handle.clone();
    if our_id > their_id {
        all_connections
            .first_ok()
            .map_err(ConnectError::AllConnectionsFailed)
            .and_then(move |(socket, their_uid)| {
                socket
                    .send((0, HandshakeMessage::ChooseConnection))
                    .map_err(ConnectError::ChooseConnection)
                    .map(move |socket| {
                        peer::from_handshaken_socket(
                            &handle_copy,
                            socket,
                            their_uid,
                            CrustUser::Node,
                        )
                    })
            })
            .into_boxed()
    } else {
        all_connections
            .map(move |(socket, their_uid)| {
                let handle_copy = handle_copy.clone();
                socket
                    .into_future()
                    .map_err(|(err, _socket)| SingleConnectionError::Socket(err))
                    .and_then(move |(msg_opt, socket)| match msg_opt {
                        None => Err(SingleConnectionError::ConnectionDropped),
                        Some(HandshakeMessage::ChooseConnection) => {
                            Ok(peer::from_handshaken_socket(
                                &handle_copy,
                                socket,
                                their_uid,
                                CrustUser::Node,
                            ))
                        }
                        Some(_msg) => Err(SingleConnectionError::UnexpectedMessage),
                    })
            })
            .buffer_unordered(128)
            .first_ok()
            .map_err(ConnectError::AllConnectionsFailed)
            .into_boxed()
    }
}

fn connect_directly(
    evloop_handle: &Handle,
    addrs: Vec<PaAddr>,
) -> BoxStream<PaStream, SingleConnectionError> {
    stream::futures_unordered(
        addrs
            .into_iter()
            .map(|addr| PaStream::direct_connect(&addr, evloop_handle))
            .collect::<Vec<_>>(),
    ).and_then(send_request_header)
        .map_err(SingleConnectionError::Io)
        .into_boxed()
}

fn handshake_incoming_connections<UID: Uid>(
    our_connect_request: ConnectRequest<UID>,
    conn_rx: UnboundedReceiver<ConnectMessage<UID>>,
    their_id: UID,
) -> BoxStream<(Socket<HandshakeMessage<UID>>, UID), SingleConnectionError> {
    conn_rx
        .map_err(|()| unreachable!())
        .infallible::<SingleConnectionError>()
        .and_then(move |(socket, connect_request)| {
            validate_connect_request(their_id, our_connect_request.name_hash, &connect_request)?;
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
    evloop_handle: &Handle,
    connections: S,
    our_connect_request: ConnectRequest<UID>,
    their_id: UID,
) -> BoxStream<(Socket<HandshakeMessage<UID>>, UID), SingleConnectionError>
where
    S: Stream<Item = PaStream, Error = SingleConnectionError> + 'static,
{
    let our_name_hash = our_connect_request.name_hash;
    let handle_copy = evloop_handle.clone();
    connections
        .map(move |stream| {
            let peer_addr = unwrap!(stream.peer_addr());
            Socket::wrap_pa(&handle_copy, stream, peer_addr)
        })
        .and_then(move |socket| {
            socket
                .send((0, HandshakeMessage::Connect(our_connect_request.clone())))
                .map_err(SingleConnectionError::Socket)
        })
        .and_then(move |socket| {
            socket.into_future().map_err(|(err, _socket)| {
                SingleConnectionError::Socket(err)
            })
        })
        .and_then(move |(msg_opt, socket)| match msg_opt {
            None => Err(SingleConnectionError::ConnectionDropped),
            Some(HandshakeMessage::Connect(connect_request)) => {
                validate_connect_request(their_id, our_name_hash, &connect_request)?;
                Ok((socket, connect_request.uid))
            }
            Some(_msg) => Err(SingleConnectionError::UnexpectedMessage),
        })
        .into_boxed()
}

/// Sends magic 8 byte string that every connection should be started with.
fn send_request_header(stream: PaStream) -> IoFuture<PaStream> {
    tokio_io::io::write_all(stream, CRUST_REQ_HEADER)
        .map(|(stream, _buf)| stream)
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
        uid: their_uid,
        name_hash: their_name_hash,
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
    rendezvous_relay: UnboundedBiChannel<Bytes>,
) -> oneshot::Receiver<Result<PaStream, RendezvousConnectError>> {
    let (conn_tx, conn_rx) = oneshot::channel();

    let connect = {
        PaStream::rendezvous_connect(rendezvous_relay, handle)
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

            let received_conn_info = unwrap!(core.run(info_rx.into_future().and_then(
                |(info, _stream)| Ok(info),
            )));

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
                Err(e) => {
                    match e {
                        SingleConnectionError::DeadChannel => true,
                        _ => false,
                    }
                }
                _ => false,
            };
            assert!(channel_is_dead);
        }
    }
}
