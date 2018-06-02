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

use futures::stream::FuturesUnordered;
use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use net::peer;
use net::peer::connect::demux::BootstrapMessage;
use net::peer::connect::handshake_message::{
    BootstrapDenyReason, BootstrapRequest, HandshakeMessage,
};
use priv_prelude::*;
use rust_sodium::crypto::box_::SecretKey;
use util;

quick_error! {
    #[derive(Debug)]
    pub enum BootstrapAcceptError {
        Socket(e: SocketError) {
            description("Error on the underlying socket")
            display("Error on the underlying socket: {}", e)
            from()
        }
        Disconnected {
            description("Disconnected from peer")
        }
        ConnectionFromOurself {
            description("Accepted connection from ourselves")
        }
        InvalidNameHash(name_hash: NameHash) {
            description("Peer is from a different network")
            display("Peer is from a different network. Invalid name hash == {:?}", name_hash)
        }
        NodeNotWhiteListed(ip: IpAddr) {
            description("Node is not whitelisted")
            display("Node {} is not whitelisted", ip)
        }
        FailedExternalReachability(errors: Vec<io::Error>) {
            description("All external reachability checks failed")
            display("All external reachability checks failed. \
                    Tried {} addresses, errors: {:?}",
                    errors.len(), errors)
        }
        ClientNotWhiteListed(ip: IpAddr) {
            description("Client is not whitelisted")
            display("Client {} is not whitelisted", ip)
        }
    }
}

/// A stream of incoming bootstrap connections.
pub struct BootstrapAcceptor {
    handle: Handle,
    peer_rx: UnboundedReceiver<BootstrapMessage>,
    handshaking: FuturesUnordered<BoxFuture<Peer, BootstrapAcceptError>>,
    config: ConfigFile,
    our_uid: Uid,
    our_sk: SecretKey,
}

impl BootstrapAcceptor {
    pub fn new(
        handle: &Handle,
        config: &ConfigFile,
        our_uid: Uid,
        our_sk: SecretKey,
    ) -> (
        BootstrapAcceptor,
        UnboundedSender<BootstrapMessage>,
    ) {
        let config = config.clone();
        let handle = handle.clone();
        let (peer_tx, peer_rx) = mpsc::unbounded();
        let handshaking =
            stream::futures_unordered(Vec::<BoxFuture<Peer, BootstrapAcceptError>>::new());
        let acceptor = BootstrapAcceptor {
            handle,
            peer_rx,
            handshaking,
            config,
            our_uid,
            our_sk,
        };
        (acceptor, peer_tx)
    }
}

impl Stream for BootstrapAcceptor {
    type Item = Peer;
    type Error = BootstrapAcceptError;

    fn poll(&mut self) -> Result<Async<Option<Peer>>, BootstrapAcceptError> {
        let stream_ended;
        loop {
            match self.peer_rx.poll() {
                Ok(Async::Ready(Some((socket, bootstrap_request)))) => {
                    let handshaker = bootstrap_accept(
                        &self.handle,
                        socket,
                        &self.config,
                        self.our_uid,
                        bootstrap_request,
                        self.our_sk.clone(),
                    );
                    self.handshaking.push(handshaker);
                }
                Ok(Async::Ready(None)) => {
                    stream_ended = true;
                    break;
                }
                Ok(Async::NotReady) => {
                    stream_ended = false;
                    break;
                }
                Err(()) => unreachable!(),
            }
        }
        let ret = match self.handshaking.poll() {
            Ok(Async::Ready(None)) => Ok(Async::NotReady),
            ret => ret,
        };
        if stream_ended && self.handshaking.is_empty() {
            return Ok(Async::Ready(None));
        }
        ret
    }
}

/// Construct a `Peer` by finishing a bootstrap accept handshake on a socket.
/// The initial `BootstrapRequest` message sent by the peer has already been read from the
/// socket.
fn bootstrap_accept(
    handle: &Handle,
    mut socket: Socket<HandshakeMessage>,
    config: &ConfigFile,
    our_uid: Uid,
    bootstrap_request: BootstrapRequest,
    our_sk: SecretKey,
) -> BoxFuture<Peer, BootstrapAcceptError> {
    let handle = handle.clone();
    let their_uid = bootstrap_request.uid;
    let their_name_hash = bootstrap_request.name_hash;
    let their_ext_reachability = bootstrap_request.ext_reachability;
    socket.use_crypto_ctx(CryptoContext::authenticated(
        bootstrap_request.uid.pkey(),
        our_sk,
    ));

    let try = move || {
        if our_uid == their_uid {
            return Err(BootstrapAcceptError::ConnectionFromOurself);
        }
        if config.network_name_hash() != their_name_hash {
            return Ok(socket
                .send((
                    0,
                    HandshakeMessage::BootstrapDenied(BootstrapDenyReason::InvalidNameHash),
                ))
                .map_err(BootstrapAcceptError::Socket)
                .and_then(move |_socket| {
                    Err(BootstrapAcceptError::InvalidNameHash(their_name_hash))
                })
                .into_boxed());
        }
        // Cache the reachability requirement config option, to make sure that it won't be
        // updated with the rest of the configuration.
        // TODO: why?
        let require_reachability = config.read().dev.as_ref().map_or(true, |dev_cfg| {
            !dev_cfg.disable_external_reachability_requirement
        });
        match config.reload() {
            Ok(()) => (),
            Err(e) => debug!("Could not read Crust config file: {:?}", e),
        };
        match their_ext_reachability {
            ExternalReachability::Required { direct_listeners } => {
                let their_ip = socket.peer_addr()?.ip();
                if !config.is_peer_whitelisted(their_ip, CrustUser::Node) {
                    let reason = BootstrapDenyReason::NodeNotWhitelisted;
                    return Ok(socket
                        .send((0, HandshakeMessage::BootstrapDenied(reason)))
                        .map_err(BootstrapAcceptError::Socket)
                        .and_then(move |_socket| {
                            Err(BootstrapAcceptError::NodeNotWhiteListed(their_ip))
                        })
                        .into_boxed());
                }

                if !require_reachability {
                    return Ok(grant_bootstrap(
                        &handle,
                        socket,
                        our_uid,
                        their_uid,
                        CrustUser::Node,
                    ).map_err(BootstrapAcceptError::Socket)
                        .into_boxed());
                }

                let connectors = {
                    direct_listeners
                        .into_iter()
                        .filter(|peer| util::ip_addr_is_global(&peer.addr.ip()))
                        .map(|peer| {
                            PaStream::direct_connect(&handle, &peer.addr, peer.pub_key, config)
                                .with_timeout(Duration::from_secs(3), &handle)
                                .and_then(|res| res.ok_or_else(|| io::ErrorKind::TimedOut.into()))
                                .into_boxed()
                        })
                        .collect::<Vec<_>>()
                };
                let connectors = stream::futures_unordered(connectors);

                Ok(connectors
                    .first_ok()
                    .then(move |res| match res {
                        Ok(_connection) => {
                            grant_bootstrap(&handle, socket, our_uid, their_uid, CrustUser::Node)
                                .map_err(BootstrapAcceptError::Socket)
                                .into_boxed()
                        }
                        Err(v) => {
                            let reason = BootstrapDenyReason::FailedExternalReachability;
                            socket
                                .send((0, HandshakeMessage::BootstrapDenied(reason)))
                                .map_err(BootstrapAcceptError::Socket)
                                .and_then(move |_socket| {
                                    Err(BootstrapAcceptError::FailedExternalReachability(v))
                                })
                                .into_boxed()
                        }
                    })
                    .into_boxed())
            }
            ExternalReachability::NotRequired => {
                let their_ip = socket.peer_addr()?.ip();
                if !config.is_peer_whitelisted(their_ip, CrustUser::Client) {
                    let reason = BootstrapDenyReason::ClientNotWhitelisted;
                    return Ok(socket
                        .send((0, HandshakeMessage::BootstrapDenied(reason)))
                        .map_err(BootstrapAcceptError::Socket)
                        .and_then(move |_socket| {
                            Err(BootstrapAcceptError::ClientNotWhiteListed(their_ip))
                        })
                        .into_boxed());
                }

                Ok(
                    grant_bootstrap(&handle, socket, our_uid, their_uid, CrustUser::Client)
                        .map_err(BootstrapAcceptError::Socket)
                        .into_boxed(),
                )
            }
        }
    };
    future::result(try()).flatten().into_boxed()
}

fn grant_bootstrap(
    handle: &Handle,
    socket: Socket<HandshakeMessage>,
    our_uid: Uid,
    their_uid: Uid,
    kind: CrustUser,
) -> BoxFuture<Peer, SocketError> {
    let handle = handle.clone();
    socket
        .send((0, HandshakeMessage::BootstrapGranted(our_uid)))
        .map(move |socket| peer::from_handshaken_socket(&handle, socket, their_uid, kind))
        .into_boxed()
}
