// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::any::Any;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::rc::Rc;

use common::{Core, CoreTimerId, Message, Priority, Socket, State};
use main::{ConnectionId, ConnectionMap, Event, PeerId};
use mio::{EventLoop, EventSet, Timeout, Token};

#[cfg(not(test))]
pub const INACTIVITY_TIMEOUT_MS: u64 = 120_000;
#[cfg(not(test))]
const HEARTBEAT_PERIOD_MS: u64 = 20_000;

#[cfg(test)]
pub const INACTIVITY_TIMEOUT_MS: u64 = 900;
#[cfg(test)]
const HEARTBEAT_PERIOD_MS: u64 = 300;

pub struct ActiveConnection {
    token: Token,
    socket: Socket,
    cm: ConnectionMap,
    our_id: PeerId,
    their_id: PeerId,
    event_tx: ::CrustEventSender,
    heartbeat: Heartbeat,
}

impl ActiveConnection {
    pub fn start(core: &mut Core,
                 el: &mut EventLoop<Core>,
                 token: Token,
                 socket: Socket,
                 cm: ConnectionMap,
                 our_id: PeerId,
                 their_id: PeerId,
                 event: Event,
                 event_tx: ::CrustEventSender) {
        debug!("Entered state ActiveConnection: {:?} -> {:?}",
               our_id,
               their_id);

        let heartbeat = match Heartbeat::new(el, token) {
            Ok(heartbeat) => heartbeat,
            Err(error) => {
                warn!("{:?} - Failed to initialize heartbeat: {:?}", our_id, error);
                let _ = el.deregister(&socket);
                let _ = event_tx.send(Event::LostPeer(their_id));
                // TODO See if this plays well with ConnectionMap manipulation below
                return;
            }
        };

        let state = Rc::new(RefCell::new(ActiveConnection {
            token: token,
            socket: socket,
            cm: cm,
            our_id: our_id,
            their_id: their_id,
            event_tx: event_tx,
            heartbeat: heartbeat,
        }));

        let _ = core.insert_state(token, state.clone());

        let mut state_mut = state.borrow_mut();
        {
            let mut guard = unwrap!(state_mut.cm.lock());
            let conn_id = guard.entry(their_id).or_insert(ConnectionId {
                active_connection: None,
                currently_handshaking: 1,
            });
            conn_id.currently_handshaking -= 1;
            conn_id.active_connection = Some(token);
        }
        let _ = state_mut.event_tx.send(event);
        state_mut.read(core, el);
    }

    fn read(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        loop {
            match self.socket.read::<Message>() {
                Ok(Some(Message::Data(data))) => {
                    let _ = self.event_tx.send(Event::NewMessage(self.their_id, data));
                    self.reset_receive_heartbeat(core, el);
                }
                Ok(Some(Message::Heartbeat)) => {
                    self.reset_receive_heartbeat(core, el);
                }
                Ok(Some(message)) => {
                    warn!("{:?} - Unexpected message: {:?}", self.our_id, message);
                    self.reset_receive_heartbeat(core, el);
                }
                Ok(None) => return,
                Err(error) => {
                    debug!("{:?} - Failed to read from socket: {:?}",
                           self.our_id,
                           error);
                    return self.terminate(core, el);
                }
            }
        }
    }

    fn write(&mut self,
             core: &mut Core,
             el: &mut EventLoop<Core>,
             msg: Option<(Message, Priority)>) {
        if let Err(error) = self.socket.write(el, self.token, msg) {
            debug!("{:?} - Failed to write socket: {:?}", self.our_id, error);
            self.terminate(core, el);
        }
    }

    fn reset_receive_heartbeat(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        if let Err(error) = self.heartbeat.reset_receive(el) {
            warn!("{:?} - Failed to reset heartbeat: {:?}", self.our_id, error);
            self.terminate(core, el);
        }
    }

    fn reset_send_heartbeat(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        if let Err(error) = self.heartbeat.reset_send(el) {
            warn!("{:?} - Failed to reset heartbeat: {:?}", self.our_id, error);
            self.terminate(core, el);
        }
    }
}

impl State for ActiveConnection {
    fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, es: EventSet) {
        if es.is_error() || es.is_hup() {
            self.terminate(core, el);
        } else {
            if es.is_writable() {
                self.write(core, el, None);
            }
            if es.is_readable() {
                self.read(core, el);
            }
        }
    }

    fn write(&mut self,
             core: &mut Core,
             el: &mut EventLoop<Core>,
             data: Vec<u8>,
             priority: Priority) {
        self.write(core, el, Some((Message::Data(data), priority)));
        self.reset_send_heartbeat(core, el);
    }

    fn terminate(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        self.heartbeat.terminate(el);
        let _ = el.deregister(&self.socket);
        let _ = core.remove_state(self.token);

        {
            let mut guard = unwrap!(self.cm.lock());
            if let Entry::Occupied(mut oe) = guard.entry(self.their_id) {
                oe.get_mut().active_connection = None;
                if oe.get().currently_handshaking == 0 {
                    let _ = oe.remove();
                }
            }
        }

        let _ = self.event_tx.send(Event::LostPeer(self.their_id));
    }

    fn timeout(&mut self, core: &mut Core, el: &mut EventLoop<Core>, timer_id: u8) {
        match self.heartbeat.timeout(el, timer_id) {
            HeartbeatAction::Send => self.write(core, el, Some((Message::Heartbeat, 0))),
            HeartbeatAction::Terminate => {
                debug!("Dropping connection to {:?} due to peer inactivity",
                       self.their_id);
                self.terminate(core, el);
            }
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

struct Heartbeat {
    recv_timeout: Timeout,
    recv_timer: CoreTimerId,
    send_timeout: Timeout,
    send_timer: CoreTimerId,
}

impl Heartbeat {
    fn new(el: &mut EventLoop<Core>, state_id: Token) -> ::Res<Self> {
        let recv_timer = CoreTimerId::new(state_id, 0);
        let recv_timeout = try!(el.timeout_ms(recv_timer, INACTIVITY_TIMEOUT_MS));

        let send_timer = CoreTimerId::new(state_id, 1);
        let send_timeout = try!(el.timeout_ms(send_timer, HEARTBEAT_PERIOD_MS));

        Ok(Heartbeat {
            recv_timeout: recv_timeout,
            recv_timer: recv_timer,
            send_timeout: send_timeout,
            send_timer: send_timer,
        })
    }

    fn timeout(&self, el: &mut EventLoop<Core>, timer_id: u8) -> HeartbeatAction {
        if timer_id == self.recv_timer.timer_id {
            HeartbeatAction::Terminate
        } else {
            if let Err(error) = el.timeout_ms(self.send_timer, HEARTBEAT_PERIOD_MS) {
                warn!("Failed to reschedule heartbeat send timer: {:?}", error);
                HeartbeatAction::Terminate
            } else {
                HeartbeatAction::Send
            }
        }
    }

    fn reset_receive(&mut self, el: &mut EventLoop<Core>) -> ::Res<()> {
        let _ = el.clear_timeout(self.recv_timeout);
        self.recv_timeout = try!(el.timeout_ms(self.recv_timer, INACTIVITY_TIMEOUT_MS));
        Ok(())
    }

    fn reset_send(&mut self, el: &mut EventLoop<Core>) -> ::Res<()> {
        let _ = el.clear_timeout(self.send_timeout);
        self.send_timeout = try!(el.timeout_ms(self.send_timer, HEARTBEAT_PERIOD_MS));
        Ok(())
    }

    fn terminate(&mut self, el: &mut EventLoop<Core>) {
        let _ = el.clear_timeout(self.recv_timeout);
        let _ = el.clear_timeout(self.send_timeout);
    }
}

enum HeartbeatAction {
    Send,
    Terminate,
}
