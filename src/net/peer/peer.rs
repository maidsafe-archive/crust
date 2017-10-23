use maidsafe_utilities::serialisation::SerialisationError;
use net::peer::PeerMessage;
use net::peer::connect::BootstrapDenyReason;
use util;
use priv_prelude::*;

#[cfg(not(test))]
pub const INACTIVITY_TIMEOUT_MS: u64 = 120_000;
#[cfg(not(test))]
const HEARTBEAT_PERIOD_MS: u64 = 20_000;

#[cfg(test)]
//pub const INACTIVITY_TIMEOUT_MS: u64 = 900;
pub const INACTIVITY_TIMEOUT_MS: u64 = 900_000;
#[cfg(test)]
//const HEARTBEAT_PERIOD_MS: u64 = 300
const HEARTBEAT_PERIOD_MS: u64 = 300_000;

/// A connection to a remote peer.
// This wraps a `Socket` and uses it to send `PeerMessage`s to peers. It also adds a heartbeat to
// keep the connection alive and detect when peers have disconnected.
//
// TODO: One problem with the implementation is that it takes serialized messages from the upper
// layer and then re-serialises them for no reason. This behaviour is inherited from the old crust
// (where `Peer` and `Socket` were the same type) but should really be fixed. The heartbeat could
// simply be encoded as a zero-byte message.
pub struct Peer<UID: Uid> {
    their_uid: UID,
    kind: CrustUser,
    socket: Socket<PeerMessage>,
    last_send_time: Instant,
    send_heartbeat_timeout: Timeout,
    recv_heartbeat_timeout: Timeout,
}

quick_error! {
    #[derive(Debug)]
    pub enum PeerError {
        Destroyed {
            description("Socket has been destroyed")
        }
        Io(e: io::Error) {
            description("Io error on socket")
            display("Io error on socket: {}", e)
            cause(e)
            from()
        }
        Deserialisation(e: SerialisationError) {
            description("Error deserialising message from peer")
            display("Error deserialising message from peer: {}", e)
            cause(e)
            from()
        }
        InactivityTimeout {
            description("connection to peer timed out")
            display("connection to peer timed out after {}s", INACTIVITY_TIMEOUT_MS / 1000)
        }
    }
}

impl From<SocketError> for PeerError {
    fn from(e: SocketError) -> PeerError {
        match e {
            SocketError::Io(e) => PeerError::Io(e),
            SocketError::Destroyed => PeerError::Destroyed,
            SocketError::Deserialisation(e) => PeerError::Deserialisation(e),
        }
    }
}

/// Construct a `Peer` from a `Socket` once we have completed the initial handshake.
pub fn from_handshaken_socket<UID: Uid, M: 'static>(
    handle: &Handle,
    socket: Socket<M>,
    their_uid: UID,
    kind: CrustUser,
) -> io::Result<Peer<UID>> {
    let now = Instant::now();
    Ok(Peer {
        socket: socket.change_message_type(),
        their_uid: their_uid,
        kind: kind,
        last_send_time: now,
        send_heartbeat_timeout: Timeout::new_at(now + Duration::from_millis(HEARTBEAT_PERIOD_MS), handle)?,
        recv_heartbeat_timeout: Timeout::new_at(now + Duration::from_millis(INACTIVITY_TIMEOUT_MS), handle)?,
    })
}

impl<UID: Uid> Peer<UID> {
    pub fn addr(&self) -> Result<SocketAddr, PeerError> {
        Ok(self.socket.peer_addr()?)
    }

    pub fn uid(&self) -> UID {
        self.their_uid
    }

    pub fn kind(&self) -> CrustUser {
        self.kind
    }

    pub fn ip(&self) -> Result<IpAddr, PeerError> {
        Ok(self.socket.peer_addr().map(|a| a.ip())?)
    }
}

impl<UID: Uid> Stream for Peer<UID> {
    type Item = Vec<u8>;
    type Error = PeerError;

    fn poll(&mut self) -> Result<Async<Option<Vec<u8>>>, PeerError> {
        let heartbeat_period = Duration::from_millis(HEARTBEAT_PERIOD_MS);
        let now = Instant::now();
        while let Async::Ready(..) = self.send_heartbeat_timeout.poll().void_unwrap() {
            self.send_heartbeat_timeout.reset(self.last_send_time + heartbeat_period);
            if now - self.last_send_time >= heartbeat_period {
                self.last_send_time = now;
                let _ = self.socket.start_send((0, PeerMessage::Heartbeat));
            }
        }

        loop {
            match self.socket.poll() {
                Err(e) => return Err(PeerError::from(e)),
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) => return Ok(Async::Ready(None)),
                Ok(Async::Ready(Some(msg))) => {
                    let instant = Instant::now() + Duration::from_millis(INACTIVITY_TIMEOUT_MS);
                    self.recv_heartbeat_timeout.reset(instant);
                    if let PeerMessage::Data(data) = msg {
                        return Ok(Async::Ready(Some(data)));
                    }
                },
            }
        }

        if let Async::Ready(..) = self.recv_heartbeat_timeout.poll().void_unwrap() {
            return Err(PeerError::InactivityTimeout);
        }

        Ok(Async::NotReady)
    }
}

impl<UID: Uid> Sink for Peer<UID> {
    type SinkItem = (Priority, Vec<u8>);
    type SinkError = PeerError;

    fn start_send(
        &mut self,
        (priority, data): (Priority, Vec<u8>),
    ) -> Result<AsyncSink<(Priority, Vec<u8>)>, PeerError> {
        match self.socket.start_send((priority, PeerMessage::Data(data)))? {
            AsyncSink::Ready => {
                self.last_send_time = Instant::now();
                Ok(AsyncSink::Ready)
            },
            AsyncSink::NotReady((priority, PeerMessage::Data(v))) => Ok(AsyncSink::NotReady((priority, v))),
            AsyncSink::NotReady(..) => unreachable!(),
        }
    }

    fn poll_complete(&mut self) -> Result<Async<()>, PeerError> {
        self.socket.poll_complete().map_err(PeerError::from)
    }
}

