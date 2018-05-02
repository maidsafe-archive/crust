// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use common::{Core, CoreTimer, CrustUser, Message, Priority, Socket, State, Uid};
use main::{ConnectionId, ConnectionMap, Event};
use mio::{Poll, Ready, Token};
use mio::timer::Timeout;
use std::any::Any;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

#[cfg(not(test))]
pub const INACTIVITY_TIMEOUT_MS: u64 = 120_000;
#[cfg(not(test))]
const HEARTBEAT_PERIOD_MS: u64 = 20_000;

#[cfg(test)]
pub const INACTIVITY_TIMEOUT_MS: u64 = 900;
#[cfg(test)]
const HEARTBEAT_PERIOD_MS: u64 = 300;

pub struct ActiveConnection<UID: Uid> {
    token: Token,
    socket: Socket,
    cm: ConnectionMap<UID>,
    our_id: UID,
    their_id: UID,
    their_role: CrustUser,
    event_tx: ::CrustEventSender<UID>,
    heartbeat: Heartbeat,
}

impl<UID: Uid> ActiveConnection<UID> {
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        token: Token,
        socket: Socket,
        cm: ConnectionMap<UID>,
        our_id: UID,
        their_id: UID,
        their_role: CrustUser,
        event: Event<UID>,
        event_tx: ::CrustEventSender<UID>,
    ) {
        trace!(
            "Entered state ActiveConnection: {:?} -> {:?}",
            our_id,
            their_id
        );

        let heartbeat = match Heartbeat::new(core, token) {
            Ok(heartbeat) => heartbeat,
            Err(e) => {
                debug!(
                    "{:?} - Failed to initialize heartbeat: {:?} - killing ActiveConnection \
                        to {:?}",
                    our_id,
                    e,
                    their_id
                );
                let _ = poll.deregister(&socket);
                let _ = event_tx.send(Event::LostPeer(their_id));
                // TODO See if this plays well with ConnectionMap<UID> manipulation below
                return;
            }
        };

        let state = Rc::new(RefCell::new(ActiveConnection {
            token: token,
            socket: socket,
            cm: cm,
            our_id: our_id,
            their_id: their_id,
            their_role: their_role,
            event_tx: event_tx,
            heartbeat: heartbeat,
        }));

        let _ = core.insert_state(token, state.clone());

        let mut state_mut = state.borrow_mut();
        {
            let mut guard = unwrap!(state_mut.cm.lock());
            {
                let conn_id = guard.entry(their_id).or_insert(ConnectionId {
                    active_connection: None,
                    currently_handshaking: 1,
                });
                conn_id.currently_handshaking -= 1;
                conn_id.active_connection = Some(token);
            }
            trace!(
                "Connection Map inserted: {:?} -> {:?}",
                their_id,
                guard.get(&their_id)
            );
        }
        let _ = state_mut.event_tx.send(event);
        state_mut.read(core, poll);
    }

    fn read(&mut self, core: &mut Core, poll: &Poll) {
        loop {
            match self.socket.read::<Message<UID>>() {
                Ok(Some(Message::Data(data))) => {
                    let _ = self.event_tx.send(Event::NewMessage(
                        self.their_id,
                        self.their_role,
                        data,
                    ));
                    self.reset_receive_heartbeat(core, poll);
                }
                Ok(Some(Message::Heartbeat)) => {
                    self.reset_receive_heartbeat(core, poll);
                }
                Ok(Some(message)) => {
                    debug!("{:?} - Unexpected message: {:?}", self.our_id, message);
                    self.reset_receive_heartbeat(core, poll);
                }
                Ok(None) => return,
                Err(e) => {
                    debug!("{:?} - Failed to read from socket: {:?}", self.our_id, e);
                    return self.terminate(core, poll);
                }
            }
        }
    }

    #[cfg(not(test))]
    /// Helper function that returns a socket address of the connection
    pub fn peer_addr(&self) -> ::Res<SocketAddr> {
        use main::CrustError;
        self.socket.peer_addr().map_err(CrustError::Common)
    }

    #[cfg(test)]
    // TODO(nbaksalyar) find a better way to mock connection IPs
    pub fn peer_addr(&self) -> ::Res<SocketAddr> {
        use std::str::FromStr;
        Ok(unwrap!(FromStr::from_str("192.168.0.1:0")))
    }

    pub fn peer_kind(&self) -> CrustUser {
        self.their_role
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, msg: Option<(Message<UID>, Priority)>) {
        if let Err(e) = self.socket.write(poll, self.token, msg) {
            debug!("{:?} - Failed to write socket: {:?}", self.our_id, e);
            self.terminate(core, poll);
        }
    }

    fn reset_receive_heartbeat(&mut self, core: &mut Core, poll: &Poll) {
        if let Err(e) = self.heartbeat.reset_receive(core) {
            debug!("{:?} - Failed to reset heartbeat: {:?}", self.our_id, e);
            self.terminate(core, poll);
        }
    }

    fn reset_send_heartbeat(&mut self, core: &mut Core, poll: &Poll) {
        if let Err(e) = self.heartbeat.reset_send(core) {
            debug!("{:?} - Failed to reset heartbeat: {:?}", self.our_id, e);
            self.terminate(core, poll);
        }
    }
}

impl<UID: Uid> State for ActiveConnection<UID> {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_error() || kind.is_hup() {
            trace!(
                "{:?} Terminating connection to peer: {:?}. \
                    Event reason: {:?} - Optional Error: {:?}",
                self.our_id,
                self.their_id,
                kind,
                self.socket.take_error()
            );
            self.terminate(core, poll);
        } else {
            if kind.is_writable() {
                self.write(core, poll, None);
            }
            if kind.is_readable() {
                self.read(core, poll);
            }
        }
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, data: Vec<u8>, priority: Priority) {
        self.write(core, poll, Some((Message::Data(data), priority)));
        self.reset_send_heartbeat(core, poll);
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        self.heartbeat.terminate(core);
        let _ = poll.deregister(&self.socket);
        let _ = core.remove_state(self.token);

        {
            let mut guard = unwrap!(self.cm.lock());
            if let Entry::Occupied(mut oe) = guard.entry(self.their_id) {
                oe.get_mut().active_connection = None;
                if oe.get().currently_handshaking == 0 {
                    let _ = oe.remove();
                }
            }
            trace!(
                "Connection Map removed: {:?} -> {:?}",
                self.their_id,
                guard.get(&self.their_id)
            );
        }

        let _ = self.event_tx.send(Event::LostPeer(self.their_id));
    }

    fn timeout(&mut self, core: &mut Core, poll: &Poll, timer_id: u8) {
        match self.heartbeat.timeout(core, timer_id) {
            HeartbeatAction::Send => self.write(core, poll, Some((Message::Heartbeat, 0))),
            HeartbeatAction::Terminate => {
                debug!(
                    "Dropping connection to {:?} due to peer inactivity",
                    self.their_id
                );
                self.terminate(core, poll);
            }
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

struct Heartbeat {
    recv_timeout: Timeout,
    recv_timer: CoreTimer,
    send_timeout: Timeout,
    send_timer: CoreTimer,
}

impl Heartbeat {
    fn new(core: &mut Core, state_id: Token) -> ::Res<Self> {
        let recv_timer = CoreTimer::new(state_id, 0);
        let recv_timeout = core.set_timeout(
            Duration::from_millis(INACTIVITY_TIMEOUT_MS),
            recv_timer,
        )?;

        let send_timer = CoreTimer::new(state_id, 1);
        let send_timeout = core.set_timeout(
            Duration::from_millis(HEARTBEAT_PERIOD_MS),
            send_timer,
        )?;

        Ok(Heartbeat {
            recv_timeout: recv_timeout,
            recv_timer: recv_timer,
            send_timeout: send_timeout,
            send_timer: send_timer,
        })
    }

    fn timeout(&mut self, core: &mut Core, timer_id: u8) -> HeartbeatAction {
        if timer_id == self.recv_timer.timer_id {
            HeartbeatAction::Terminate
        } else {
            core.set_timeout(Duration::from_millis(HEARTBEAT_PERIOD_MS), self.send_timer)
                .map(|t| {
                    self.send_timeout = t;
                    HeartbeatAction::Send
                })
                .unwrap_or_else(|e| {
                    debug!("Failed to reschedule heartbeat send timer: {:?}", e);
                    HeartbeatAction::Terminate
                })
        }
    }

    fn reset_receive(&mut self, core: &mut Core) -> ::Res<()> {
        let _ = core.cancel_timeout(&self.recv_timeout);
        self.recv_timeout = core.set_timeout(
            Duration::from_millis(INACTIVITY_TIMEOUT_MS),
            self.recv_timer,
        )?;
        Ok(())
    }

    fn reset_send(&mut self, core: &mut Core) -> ::Res<()> {
        let _ = core.cancel_timeout(&self.send_timeout);
        self.send_timeout = core.set_timeout(
            Duration::from_millis(HEARTBEAT_PERIOD_MS),
            self.send_timer,
        )?;
        Ok(())
    }

    fn terminate(&mut self, core: &mut Core) {
        let _ = core.cancel_timeout(&self.recv_timeout);
        let _ = core.cancel_timeout(&self.send_timeout);
    }
}

enum HeartbeatAction {
    Send,
    Terminate,
}
