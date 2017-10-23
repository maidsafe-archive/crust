use futures::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use futures::stream::FuturesUnordered;
use net::peer;
use net::peer::connect::handshake_message::{HandshakeMessage, BootstrapRequest, BootstrapDenyReason};
use util;
use priv_prelude::*;

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
            display("All external reachability checks failed. Tried {} addresses, errors: {:?}", errors.len(), errors)
        }
        ClientNotWhiteListed(ip: IpAddr) {
            description("Client is not whitelisted")
            display("Client {} is not whitelisted", ip)
        }
    }
}

/// A stream of incoming bootstrap connections.
pub struct BootstrapAcceptor<UID: Uid> {
    handle: Handle,
    peer_rx: UnboundedReceiver<(Socket<HandshakeMessage<UID>>, BootstrapRequest<UID>)>,
    handshaking: FuturesUnordered<BoxFuture<Peer<UID>, BootstrapAcceptError>>,
    config: ConfigFile,
    our_uid: UID,
}

impl<UID: Uid> BootstrapAcceptor<UID> {
    pub fn new(
        handle: &Handle,
        config: ConfigFile,
        our_uid: UID,
    ) -> (BootstrapAcceptor<UID>, UnboundedSender<(Socket<HandshakeMessage<UID>>, BootstrapRequest<UID>)>) {
        let handle = handle.clone();
        let (peer_tx, peer_rx) = mpsc::unbounded();
        let handshaking = stream::futures_unordered(Vec::<BoxFuture<Peer<UID>, BootstrapAcceptError>>::new());
        let acceptor = BootstrapAcceptor {
            handle,
            peer_rx,
            handshaking,
            config,
            our_uid,
        };
        (acceptor, peer_tx)
    }
}

impl<UID: Uid> Stream for BootstrapAcceptor<UID> {
    type Item = Peer<UID>;
    type Error = BootstrapAcceptError;

    fn poll(&mut self) -> Result<Async<Option<Peer<UID>>>, BootstrapAcceptError> {
        let stream_ended;
        loop {
            match self.peer_rx.poll() {
                Ok(Async::Ready(Some((socket, bootstrap_request)))) => {
                    let handshaker = bootstrap_accept(
                        &self.handle,
                        socket,
                        self.config.clone(),
                        self.our_uid,
                        bootstrap_request,
                    );
                    self.handshaking.push(handshaker);
                },
                Ok(Async::Ready(None)) => {
                    stream_ended = true;
                    break;
                },
                Ok(Async::NotReady) => {
                    stream_ended = false;
                    break;
                },
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
fn bootstrap_accept<UID: Uid>(
    handle: &Handle,
    socket: Socket<HandshakeMessage<UID>>,
    config: ConfigFile,
    our_uid: UID,
    bootstrap_request: BootstrapRequest<UID>,
) -> BoxFuture<Peer<UID>, BootstrapAcceptError>
{
    let handle = handle.clone();
    let their_uid = bootstrap_request.uid;
    let their_name_hash = bootstrap_request.name_hash;
    let their_ext_reachability = bootstrap_request.ext_reachability;
    let try = move || {
        if our_uid == their_uid {
            return Err(BootstrapAcceptError::ConnectionFromOurself);
        }
        if config.network_name_hash() != their_name_hash {
            return Ok(
                socket.send((0, HandshakeMessage::BootstrapDenied(BootstrapDenyReason::InvalidNameHash)))
                .map_err(BootstrapAcceptError::Socket)
                .and_then(move |_socket| {
                    Err(BootstrapAcceptError::InvalidNameHash(their_name_hash))
                })
                .into_boxed()
            );
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
                    return Ok(
                        socket.send((0, HandshakeMessage::BootstrapDenied(reason)))
                        .map_err(BootstrapAcceptError::Socket)
                        .and_then(move |_socket| {
                            Err(BootstrapAcceptError::NodeNotWhiteListed(their_ip))
                        })
                        .into_boxed()
                    );
                }

                if !require_reachability {
                    return Ok(
                        grant_bootstrap(&handle, socket, our_uid, their_uid, CrustUser::Node)
                        .map_err(BootstrapAcceptError::Socket)
                        .into_boxed()
                    );
                }

                let connectors = {
                    direct_listeners
                    .into_iter()
                    .filter(|addr| util::ip_addr_is_global(&addr.ip()))
                    .map(|addr| {
                        TcpStream::connect(&addr, &handle)
                        .with_timeout(&handle, Duration::from_secs(3), io::ErrorKind::TimedOut.into())
                        .into_boxed()
                    })
                    .collect::<Vec<_>>()
                };
                let connectors = stream::futures_unordered(connectors);

                return Ok(
                    connectors
                    .first_ok()
                    .then(move |res| {
                        match res {
                            Ok(_connection) => {
                                grant_bootstrap(&handle, socket, our_uid, their_uid, CrustUser::Node)
                                .map_err(BootstrapAcceptError::Socket)
                                .into_boxed()
                            },
                            Err(v) => {
                                let reason = BootstrapDenyReason::FailedExternalReachability;
                                socket.send((0, HandshakeMessage::BootstrapDenied(reason)))
                                .map_err(BootstrapAcceptError::Socket)
                                .and_then(move |_socket| {
                                    Err(BootstrapAcceptError::FailedExternalReachability(v))
                                })
                                .into_boxed()
                            },
                        }
                    })
                    .into_boxed()
                );
            },
            ExternalReachability::NotRequired => {
                let their_ip = socket.peer_addr()?.ip();
                if !config.is_peer_whitelisted(their_ip, CrustUser::Client) {
                    let reason = BootstrapDenyReason::ClientNotWhitelisted;
                    return Ok(
                        socket.send((0, HandshakeMessage::BootstrapDenied(reason)))
                        .map_err(BootstrapAcceptError::Socket)
                        .and_then(move |_socket| {
                            Err(BootstrapAcceptError::ClientNotWhiteListed(their_ip))
                        })
                        .into_boxed()
                    );
                }

                Ok(
                    grant_bootstrap(&handle, socket, our_uid, their_uid, CrustUser::Client)
                    .map_err(BootstrapAcceptError::Socket)
                    .into_boxed()
                )
            },
        }
    };
    future::result(try())
    .flatten()
    .into_boxed()
}

fn grant_bootstrap<UID: Uid>(
    handle: &Handle,
    socket: Socket<HandshakeMessage<UID>>,
    our_uid: UID,
    their_uid: UID,
    kind: CrustUser,
) -> BoxFuture<Peer<UID>, SocketError> {
    let handle = handle.clone();
    socket.send((0, HandshakeMessage::BootstrapGranted(our_uid)))
    .and_then(move |socket| {
        peer::from_handshaken_socket(&handle, socket, their_uid, kind)
        .map_err(SocketError::Io)
    })
    .into_boxed()
}

