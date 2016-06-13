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

use core::{Context, Core, Priority, State};
use service::{ConnectionId, ConnectionMap};
use event::Event;
use message::Message;
use mio::{EventLoop, EventSet, Timeout, TimerError, Token};
use peer_id::PeerId;
use socket::Socket;
use std::rc::Rc;
use std::cell::RefCell;

#[cfg(not(test))]
pub const INACTIVITY_TIMEOUT_MS: u64 = 60_000;
#[cfg(not(test))]
const HEARTBEAT_PERIOD_MS: u64 = 20_000;

#[cfg(test)]
pub const INACTIVITY_TIMEOUT_MS: u64 = 900;
#[cfg(test)]
const HEARTBEAT_PERIOD_MS: u64 = 300;

pub struct ActiveConnection {
    token: Token,
    context: Context,
    socket: Socket,
    cm: ConnectionMap,
    their_id: PeerId,
    our_id: PeerId,
    event_tx: ::CrustEventSender,
    heartbeat: Heartbeat,
}

impl ActiveConnection {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 token: Token,
                 socket: Socket,
                 cm: ConnectionMap,
                 their_id: PeerId,
                 our_id: PeerId,
                 event: Event,
                 event_tx: ::CrustEventSender) {
        debug!("Entered state ActiveConnection: {:?} -> {:?}",
               our_id,
               their_id);

        let context = core.get_new_context();

        let heartbeat = match Heartbeat::new(core, event_loop, context) {
            Ok(heartbeat) => heartbeat,
            Err(error) => {
                warn!("{:?} - Failed to initialize heartbeat: {:?}", our_id, error);
                let _ = event_loop.deregister(&socket);
                let _ = event_tx.send(Event::LostPeer(their_id));
                return;
            }
        };

        let state = Rc::new(RefCell::new(ActiveConnection {
            token: token,
            context: context,
            socket: socket,
            cm: cm,
            their_id: their_id,
            our_id: our_id,
            event_tx: event_tx,
            heartbeat: heartbeat,
        }));

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, state.clone());

        let mut state_mut = state.borrow_mut();
        {
            let mut guard = state_mut.cm.lock().unwrap();
            let conn_id = guard.entry(their_id).or_insert(ConnectionId {
                active_connection: None,
                currently_handshaking: 1,
            });
            conn_id.currently_handshaking -= 1;
            conn_id.active_connection = Some(context);
        }
        let _ = state_mut.event_tx.send(event);
        state_mut.read(core, event_loop);
    }

    fn read(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        loop {
            match self.socket.read::<Message>() {
                Ok(Some(Message::Data(data))) => {
                    let _ = self.event_tx.send(Event::NewMessage(self.their_id, data));
                    self.reset_receive_heartbeat(core, event_loop);
                }
                Ok(Some(Message::Heartbeat)) => {
                    self.reset_receive_heartbeat(core, event_loop);
                }
                Ok(Some(message)) => {
                    warn!("{:?} - Unexpected message: {:?}", self.our_id, message);
                    self.reset_receive_heartbeat(core, event_loop);
                }
                Ok(None) => return,
                Err(error) => {
                    error!("{:?} - Failed to read from socket: {:?}",
                           self.our_id,
                           error);
                    return self.terminate(core, event_loop);
                }
            }
        }
    }

    fn write(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             msg: Option<(Message, Priority)>) {
        if let Err(error) = self.socket.write(event_loop, self.token, msg) {
            debug!("{:?} - Failed to write socket: {:?}", self.our_id, error);
            self.terminate(core, event_loop);
        }
    }

    fn reset_receive_heartbeat(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Err(error) = self.heartbeat.reset_receive(event_loop) {
            warn!("{:?} - Failed to reset heartbeat: {:?}", self.our_id, error);
            self.terminate(core, event_loop);
        }
    }

    fn reset_send_heartbeat(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Err(error) = self.heartbeat.reset_send(event_loop) {
            warn!("{:?} - Failed to reset heartbeat: {:?}", self.our_id, error);
            self.terminate(core, event_loop);
        }
    }
}

impl State for ActiveConnection {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet) {
        if event_set.is_error() || event_set.is_hup() {
            self.terminate(core, event_loop);
        } else {
            if event_set.is_writable() {
                self.write(core, event_loop, None);
            }
            if event_set.is_readable() {
                self.read(core, event_loop);
            }
        }
    }

    fn write(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             data: Vec<u8>,
             priority: Priority) {
        self.write(core, event_loop, Some((Message::Data(data), priority)));
        self.reset_send_heartbeat(core, event_loop);
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        debug!("{:?} - Terminating peer {:?}", self.our_id, self.their_id);
        self.heartbeat.terminate(core, event_loop);

        if let Err(error) = event_loop.deregister(&self.socket) {
            warn!("{:?} - Failed to deregister socket: {:?}",
                  self.our_id,
                  error);
        }

        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);

        {
            let mut guard = self.cm.lock().unwrap();
            let remove = {
                let conn_id = guard.get_mut(&self.their_id).expect("Logic Error");
                conn_id.active_connection = None;
                conn_id.currently_handshaking == 0
            };
            if remove {
                let _ = guard.remove(&self.their_id);
            }
        }

        let _ = self.event_tx.send(Event::LostPeer(self.their_id));
    }

    fn timeout(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, token: Token) {
        match self.heartbeat.timeout(event_loop, token) {
            HeartbeatAction::None => (),
            HeartbeatAction::Send => self.write(core, event_loop, Some((Message::Heartbeat, 0))),
            HeartbeatAction::Terminate => {
                // TODO Disabling heartbeat for now to make testing easier
                // debug!("Dropping connection to {:?} due to peer inactivity",
                //        self.their_id);
                error!("{:?} - This connection to {:?} would have been dropped due to peer \
                        inactivity. Ignoring right now.",
                       self.our_id,
                       self.their_id);
                // self.terminate(core, event_loop);
            }
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

struct Heartbeat {
    recv_timeout: Timeout,
    recv_token: Token,
    send_timeout: Timeout,
    send_token: Token,
}

impl Heartbeat {
    fn new(core: &mut Core, event_loop: &mut EventLoop<Core>, context: Context) -> ::Res<Self> {
        let recv_token = core.get_new_token();
        let recv_timeout = try!(event_loop.timeout_ms(recv_token, INACTIVITY_TIMEOUT_MS));
        let _ = core.insert_context(recv_token, context);

        let send_token = core.get_new_token();
        let send_timeout = try!(event_loop.timeout_ms(send_token, HEARTBEAT_PERIOD_MS));
        let _ = core.insert_context(send_token, context);

        Ok(Heartbeat {
            recv_timeout: recv_timeout,
            recv_token: recv_token,
            send_timeout: send_timeout,
            send_token: send_token,
        })
    }

    fn timeout(&self, event_loop: &mut EventLoop<Core>, token: Token) -> HeartbeatAction {
        // if token == self.recv_token {
        //     return HeartbeatAction::Terminate;
        // }
        if token == self.send_token {
            return if let Err(error) =
                          event_loop.timeout_ms(self.send_token, HEARTBEAT_PERIOD_MS) {
                warn!("Failed to reschedule heartbeat send timer: {:?}", error);
                HeartbeatAction::Terminate
            } else {
                HeartbeatAction::Send
            };
        }

        HeartbeatAction::None
    }

    fn reset_receive(&mut self, event_loop: &mut EventLoop<Core>) -> Result<(), TimerError> {
        let _ = event_loop.clear_timeout(self.recv_timeout);
        self.recv_timeout = try!(event_loop.timeout_ms(self.recv_token, INACTIVITY_TIMEOUT_MS));
        Ok(())
    }

    fn reset_send(&mut self, event_loop: &mut EventLoop<Core>) -> Result<(), TimerError> {
        let _ = event_loop.clear_timeout(self.send_timeout);
        self.send_timeout = try!(event_loop.timeout_ms(self.send_token, HEARTBEAT_PERIOD_MS));
        Ok(())
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = event_loop.clear_timeout(self.recv_timeout);
        let _ = core.remove_context(self.recv_token);

        let _ = event_loop.clear_timeout(self.send_timeout);
        let _ = core.remove_context(self.send_token);
    }
}

enum HeartbeatAction {
    // Do nothing
    None,
    // Send heartbeat message to the peer
    Send,
    // Terminate the connection
    Terminate,
}
