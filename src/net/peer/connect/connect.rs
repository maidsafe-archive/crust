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
use futures::sync::mpsc::UnboundedReceiver;

use net::nat;
use net::peer;
use net::peer::connect::demux::ConnectMessage;
use net::peer::connect::handshake_message::{ConnectRequest, HandshakeMessage};
use p2p::TcpStreamExt;
use priv_prelude::*;

const TIMEOUT_SEC: u64 = 60;

quick_error! {
    #[derive(Debug)]
    pub enum ConnectError {
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
        RendezvousConnect {
            description("rendezvous connect failed")
        }
        RequestedConnectToSelf {
            description("requested a connection to ourselves")
        }
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
pub fn connect<UID: Uid, C>(
    handle: &Handle,
    name_hash: NameHash,
    our_uid: UID,
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
    // TODO(povilas): respect `whitelisted_node_ips` config
    // TODO(povilas): handle incoming direct connections

    let try = move || {
        let our_connect_request = ConnectRequest {
            uid: our_uid,
            name_hash: name_hash,
        };

        let handle0 = handle.clone();
        let connection = TcpStream::rendezvous_connect(relay_channel, handle)
            .map_err(|_| SingleConnectionError::RendezvousConnect)
            .map(move |stream| {
                let peer_addr = unwrap!(stream.peer_addr());
                let sock = Socket::wrap_tcp(&handle0, stream, peer_addr);
                sock
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
                    validate_connect_request(our_uid, name_hash, &connect_request)?;
                    Ok((socket, connect_request.uid))
                }
                Some(_msg) => Err(SingleConnectionError::UnexpectedMessage),
            });

        let handle1 = handle.clone();
        let chosen_peer = connection
            .map_err(|e| ConnectError::AllConnectionsFailed(vec![e]))
            .and_then(move |(socket, their_uid)| {
                peer::from_handshaken_socket(&handle1, socket, their_uid, CrustUser::Node)
                    .map_err(ConnectError::Io)
            })
            .into_boxed();

        Ok(chosen_peer)
    };

    future::result(try()).flatten().into_boxed()
}

/// Our and their name hashes must match and our ID must not be equal to their ID.
fn validate_connect_request<UID: Uid>(
    our_uid: UID,
    our_name_hash: NameHash,
    connect_request: &ConnectRequest<UID>,
) -> Result<(), SingleConnectionError> {
    let &ConnectRequest {
        uid: their_uid,
        name_hash: their_name_hash,
    } = connect_request;
    if our_uid == connect_request.uid {
        return Err(SingleConnectionError::RequestedConnectToSelf);
    }
    if our_name_hash != their_name_hash {
        return Err(SingleConnectionError::InvalidNameHash(their_name_hash));
    }
    Ok(())
}
