use std::sync::{Arc, Mutex};
use futures::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use log::LogLevel;

use net::listener::SocketIncoming;
use net::peer::connect::handshake_message::{HandshakeMessage, BootstrapRequest, ConnectRequest};
use net::peer::connect::BootstrapAcceptor;
use net::peer::connect::connect::connect;
use net::peer::connect::stun;
use priv_prelude::*;

/// Demultiplexes the incoming stream of connections on the main listener and routes them to either
/// the bootstrap acceptor (if there is one), or to the appropriate connection handler.
pub struct Demux<UID: Uid> {
    inner: Arc<DemuxInner<UID>>,
}

struct DemuxInner<UID: Uid> {
    bootstrap_handler: Mutex<Option<UnboundedSender<(Socket<HandshakeMessage<UID>>, BootstrapRequest<UID>)>>>,
    connection_handler: Mutex<HashMap<UID, UnboundedSender<(Socket<HandshakeMessage<UID>>, ConnectRequest<UID>)>>>,
}

impl<UID: Uid> Demux<UID> {
    /// Create a demultiplexer from a stream of incoming peers.
    pub fn new(
        handle: &Handle,
        incoming: SocketIncoming,
    ) -> Demux<UID> {
        let inner = Arc::new(DemuxInner {
            bootstrap_handler: Mutex::new(None),
            connection_handler: Mutex::new(HashMap::new()),
        });
        let inner_cloned = inner.clone();
        let handle0 = handle.clone();
        let handler_task = {
            incoming
            .log_errors(LogLevel::Error, "listener errored!")
            .map(move |socket| {
                let socket = socket.change_message_type::<HandshakeMessage<UID>>();

                handle_incoming(&handle0, inner_cloned.clone(), socket)
                .log_error(LogLevel::Debug, "handling incoming connection")
            })
            .buffer_unordered(128)
            .for_each(|()| Ok(()))
            .infallible()
        };
        handle.spawn(handler_task);
        Demux {
            inner: inner,
        }
    }

    pub fn bootstrap_acceptor(
        &self,
        handle: &Handle,
        config: ConfigFile,
        our_uid: UID,
    ) -> BootstrapAcceptor<UID> {
        let (acceptor, peer_tx) = BootstrapAcceptor::new(handle, config, our_uid);
        let mut bootstrap_handler = unwrap!(self.inner.bootstrap_handler.lock());
        *bootstrap_handler = Some(peer_tx);
        acceptor
    }

    pub fn connect(
        &self,
        handle: &Handle,
        name_hash: NameHash,
        our_info: PrivConnectionInfo<UID>,
        their_info: PubConnectionInfo<UID>,
        config: ConfigFile,
    ) -> BoxFuture<Peer<UID>, ConnectError> {
        let their_uid = their_info.id;
        let peer_rx = {
            let (peer_tx, peer_rx) = mpsc::unbounded();
            let mut connection_handler = unwrap!(self.inner.connection_handler.lock());
            let _ = connection_handler.insert(their_uid, peer_tx);
            peer_rx
        };

        connect(handle, name_hash, our_info, their_info, config, peer_rx)
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum IncomingError {
        TimedOut {
            description("timed out waiting for the peer to send their request")
        }
        Socket(e: SocketError) {
            description("error on the socket")
            display("error on the socket: {}", e)
            cause(e)
        }
        UnexpectedMessage {
            description("the peer sent an unexpected message type")
        }
        Disconnected {
            description("the remote peer disconnected")
        }
        TimerIo(e: io::Error) {
            description("io error creating tokio timer")
            display("io error creating tokio timer: {}", e)
            cause(e)
        }
    }
}

fn handle_incoming<UID: Uid>(
    handle: &Handle,
    inner: Arc<DemuxInner<UID>>,
    socket: Socket<HandshakeMessage<UID>>,
) -> BoxFuture<(), IncomingError> {
    socket
    .into_future()
    .map_err(|(e, _s)| IncomingError::Socket(e))
    .with_timeout(&handle, Duration::from_secs(10), IncomingError::TimedOut)
    .and_then(move |(msg_opt, socket)| {
        let msg = match msg_opt {
            Some(msg) => msg,
            None => return future::err(IncomingError::Disconnected).into_boxed(),
        };
        match msg {
            HandshakeMessage::BootstrapRequest(bootstrap_request) => {
                let bootstrap_handler_opt = unwrap!(inner.bootstrap_handler.lock());
                if let Some(ref bootstrap_handler) = bootstrap_handler_opt.as_ref() {
                    let _ = bootstrap_handler.unbounded_send((socket, bootstrap_request));
                }
                future::ok(()).into_boxed()
            },
            HandshakeMessage::Connect(connect_request) => {
                let connection_handler_map = unwrap!(inner.connection_handler.lock());
                if let Some(ref connection_handler) = connection_handler_map.get(&connect_request.uid) {
                    let _ = connection_handler.unbounded_send((socket, connect_request));
                }
                future::ok(()).into_boxed()
            },
            HandshakeMessage::EchoAddrReq => {
                stun::stun_respond(socket)
                .map_err(IncomingError::Socket)
                .into_boxed()
            },
            _ => future::err(IncomingError::UnexpectedMessage).into_boxed(),
        }
    })
    .into_boxed()
}

