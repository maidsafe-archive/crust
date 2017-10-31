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

use futures::sync::mpsc::UnboundedReceiver;
use net::nat;
use net::peer;
use net::peer::connect::demux::ConnectMessage;
use net::peer::connect::handshake_message::{ConnectRequest, HandshakeMessage};
use priv_prelude::*;

const TIMEOUT_SEC: u64 = 60;

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
    }
}

/// Perform a rendezvous connect to a peer. Both peers call this simultaneously using
/// `PubConnectionInfo` they received from the other peer out-of-band.
pub fn connect<UID: Uid>(
    handle: &Handle,
    name_hash: NameHash,
    our_info: PrivConnectionInfo<UID>,
    their_info: PubConnectionInfo<UID>,
    config: ConfigFile,
    peer_rx: UnboundedReceiver<ConnectMessage<UID>>,
) -> BoxFuture<Peer<UID>, ConnectError> {
    let try = move || {
        let handle = handle.clone();
        let their_info = their_info;
        let our_uid = our_info.id;
        let their_uid = their_info.id;

        if our_uid == their_uid {
            return Err(ConnectError::RequestedConnectToSelf);
        }

        let our_connect_request = ConnectRequest {
            uid: our_uid,
            name_hash: name_hash,
        };

        let direct_incoming = {
            let our_connect_request = our_connect_request.clone();
            peer_rx
            .map_err(|()| unreachable!())
            .infallible::<SingleConnectionError>()
            .and_then(move |(socket, connect_request)| {
                validate_connect_request(their_uid, name_hash, &connect_request)?;
                Ok({
                    socket
                    .send((0, HandshakeMessage::Connect(our_connect_request.clone())))
                    .map_err(SingleConnectionError::Socket)
                    .map(move |socket| (socket, their_uid))
                })
            })
            .and_then(|f| f)
        };

        let mut their_direct = their_info.for_direct;
        let mut their_hole_punch = their_info.for_hole_punch;
        if let Some(ref whitelisted_node_ips) = config.read().whitelisted_node_ips {
            their_direct.retain(|s| whitelisted_node_ips.contains(&s.ip()));
            their_hole_punch.retain(|s| whitelisted_node_ips.contains(&s.ip()));
        }

        let other_connections = {
            let handle = handle.clone();
            let direct_connections = {
                let connectors = {
                    their_direct
                        .into_iter()
                        .map(|addr| {
                            TcpStream::connect(&addr, &handle).map(move |stream| (stream, addr))
                        })
                        .collect::<Vec<_>>()
                };
                stream::futures_unordered(connectors)
            };

            let connections = if let Some(listen_socket) = our_info.hole_punch_socket {
                let hole_punch_connections = {
                    nat::tcp_hole_punch(&handle, listen_socket, &their_hole_punch)
                        .map_err(ConnectError::Io)
                }?;
                direct_connections
                    .select(hole_punch_connections)
                    .into_boxed()
            } else {
                direct_connections.into_boxed()
            };

            let handle0 = handle.clone();
            connections
                .map_err(SingleConnectionError::Io)
                .map(move |(stream, addr)| {
                    Socket::wrap_tcp(&handle0, stream, addr)
                })
                .and_then(move |socket| {
                    socket
                        .send((0, HandshakeMessage::Connect(our_connect_request.clone())))
                        .map_err(SingleConnectionError::Socket)
                })
                .map(move |socket| {
                    socket
                        .into_future()
                        .map_err(|(err, _socket)| SingleConnectionError::Socket(err))
                        .with_timeout(
                            &handle,
                            Duration::from_secs(TIMEOUT_SEC),
                            SingleConnectionError::TimedOut,
                        )
                })
                .buffer_unordered(128)
                .and_then(move |(msg_opt, socket)| match msg_opt {
                    None => Err(SingleConnectionError::ConnectionDropped),
                    Some(HandshakeMessage::Connect(connect_request)) => {
                        validate_connect_request(their_uid, name_hash, &connect_request)?;
                        Ok((socket, their_uid))
                    }
                    Some(_msg) => Err(SingleConnectionError::UnexpectedMessage),
                })
        };

        let all_connections = direct_incoming.select(other_connections);

        let timeout = {
            Timeout::new(Duration::from_secs(TIMEOUT_SEC), &handle).map_err(ConnectError::Io)
        }?;
        let chosen_peer = if our_uid > their_uid {
            let handle = handle.clone();
            all_connections
                .until(timeout.infallible())
                .first_ok()
                .map_err(ConnectError::AllConnectionsFailed)
                .and_then(move |(socket, their_uid)| {
                    socket
                        .send((0, HandshakeMessage::ChooseConnection))
                        .map_err(ConnectError::ChooseConnection)
                        .and_then(move |socket| {
                            peer::from_handshaken_socket(
                                &handle,
                                socket,
                                their_uid,
                                CrustUser::Node,
                            ).map_err(ConnectError::Io)
                        })
                })
                .into_boxed()
        } else {
            let handle = handle.clone();
            all_connections
                .map(move |(socket, their_uid)| {
                    let handle = handle.clone();
                    socket
                        .into_future()
                        .map_err(|(err, _socket)| SingleConnectionError::Socket(err))
                        .and_then(move |(msg_opt, socket)| match msg_opt {
                            None => Err(SingleConnectionError::ConnectionDropped),
                            Some(HandshakeMessage::ChooseConnection) => {
                                peer::from_handshaken_socket(
                                    &handle,
                                    socket,
                                    their_uid,
                                    CrustUser::Node,
                                ).map_err(SingleConnectionError::Io)
                            }
                            Some(_msg) => Err(SingleConnectionError::UnexpectedMessage),
                        })
                })
                .buffer_unordered(128)
                .until(timeout.infallible())
                .first_ok()
                .map_err(ConnectError::AllConnectionsFailed)
                .into_boxed()
        };

        Ok(chosen_peer)
    };

    future::result(try()).flatten().into_boxed()
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
