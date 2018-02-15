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

use net::peer;
use net::peer::connect::handshake_message::{BootstrapDenyReason, BootstrapRequest,
                                            HandshakeMessage};
use priv_prelude::*;
use rust_sodium::crypto::box_::{PublicKey, SecretKey};

quick_error! {
    /// Error returned when we fail to connect to some specific peer.
    #[derive(Debug)]
    pub enum TryPeerError {
        Connect(e: io::Error) {
            description("IO error connecting to remote peer")
            display("IO error connecting to remote peer: {}", e)
            from(e)
        }
        Handshake(e: ConnectHandshakeError) {
            description("Error during peer handshake")
            display("Error during peer handshake: {}", e)
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ConnectHandshakeError {
        BootstrapDenied(e: BootstrapDenyReason) {
            description("Bootstrap denied")
            display("Bootstrap denied. reason: {:?}", e)
            from(e)
        }
        Io(e: io::Error) {
            description("io error on the socket")
            display("io error on the socket: {}", e)
            cause(e)
            from()
        }
        InvalidResponse {
            description("Invalid response from peer")
        }
        Disconnected {
            description("Disconnected from peer")
        }
        TimedOut {
            description("timed out performing handshake")
        }
        Encrypt(e: CryptoError) {
            description("Error encrypting request to peer")
            display("Error encrypting request to peer: {}", e)
            cause(e)
        }
        Decrypt(e: CryptoError) {
            description("Error decrypting message from peer")
            display("Error decrypting message from peer: {}", e)
            cause(e)
        }
    }
}

impl From<SocketError> for ConnectHandshakeError {
    fn from(e: SocketError) -> ConnectHandshakeError {
        match e {
            SocketError::Io(e) => ConnectHandshakeError::Io(e),
            SocketError::Destroyed => ConnectHandshakeError::Disconnected,
            SocketError::Encrypt(e) => ConnectHandshakeError::Encrypt(e),
            SocketError::Decrypt(e) => ConnectHandshakeError::Decrypt(e),
        }
    }
}

/// Try to bootstrap to the given peer.
pub fn try_peer<UID: Uid>(
    handle: &Handle,
    addr: &PaAddr,
    config: &ConfigFile,
    request: BootstrapRequest<UID>,
    our_sk: SecretKey,
    their_pk: PublicKey,
) -> BoxFuture<Peer<UID>, TryPeerError> {
    let handle0 = handle.clone();
    let handle1 = handle.clone();
    let addr = *addr;
    PaStream::direct_connect(&addr, handle, config)
        .map(move |(stream, _peer_addr)| {
            Socket::wrap_pa(
                &handle0,
                stream,
                addr,
                CryptoContext::anonymous_encrypt(their_pk),
            )
        })
        .with_timeout(Duration::from_secs(10), handle)
        .and_then(|res| res.ok_or_else(|| io::ErrorKind::TimedOut.into()))
        .map_err(TryPeerError::Connect)
        .and_then(move |socket| {
            bootstrap_connect_handshake(&handle1, socket, request, our_sk, their_pk)
                .map_err(TryPeerError::Handshake)
        })
        .into_boxed()
}

/// Construct a `Peer` by performing a bootstrap connection handshake on a socket.
pub fn bootstrap_connect_handshake<UID: Uid>(
    handle: &Handle,
    socket: Socket<HandshakeMessage<UID>>,
    request: BootstrapRequest<UID>,
    our_sk: SecretKey,
    their_pk: PublicKey,
) -> BoxFuture<Peer<UID>, ConnectHandshakeError> {
    let handle0 = handle.clone();
    let msg = HandshakeMessage::BootstrapRequest(request);
    socket
        .send((0, msg))
        .map_err(ConnectHandshakeError::from)
        .and_then(move |mut socket| {
            socket.use_crypto_ctx(CryptoContext::authenticated(their_pk, our_sk));
            socket
                .into_future()
                .map_err(|(e, _)| ConnectHandshakeError::from(e))
                .and_then(move |(msg_opt, socket)| match msg_opt {
                    Some(HandshakeMessage::BootstrapGranted(peer_uid)) => {
                        Ok(peer::from_handshaken_socket(
                            &handle0,
                            socket,
                            peer_uid,
                            CrustUser::Node,
                        ))
                    }
                    Some(HandshakeMessage::BootstrapDenied(reason)) => {
                        Err(ConnectHandshakeError::BootstrapDenied(reason))
                    }
                    Some(..) => Err(ConnectHandshakeError::InvalidResponse),
                    None => Err(ConnectHandshakeError::Disconnected),
                })
        })
        .with_timeout(Duration::from_secs(9), handle)
        .and_then(|res| res.ok_or(ConnectHandshakeError::TimedOut))
        .into_boxed()
}
