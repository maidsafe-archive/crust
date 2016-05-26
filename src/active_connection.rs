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

use mio::{EventLoop, EventSet, Handler, PollOpt, Timeout, TimerError, Token};
use std::any::Any;
use std::io::{Read, Write};

use core::{Core, Context, State};
use event::Event;
use message::Message;
use peer_id::PeerId;
use service::SharedConnectionMap;
use socket::Socket;

const HEARTBEAT_PERIOD_MS: u64 = 20_000;

pub struct ActiveConnection {
    connection_map: SharedConnectionMap,
    context: Context,
    event_tx: ::CrustEventSender,
    heartbeat: Heartbeat,
    peer_id: PeerId,
    socket: Socket,
    token: Token,
    event_set: EventSet,
}

impl ActiveConnection {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 context: Context,
                 connection_map: SharedConnectionMap,
                 peer_id: PeerId,
                 socket: Socket,
                 token: Token,
                 event_tx: ::CrustEventSender) {
        debug!("Entered state ActiveConnection");

        let event_set = EventSet::error() | EventSet::hup() | EventSet::readable();

        if let Err(error) = event_loop.reregister(&socket,
                                                  token,
                                                  event_set,
                                                  PollOpt::edge())
        {
            error!("Failed to reregister socker: {:?}", error);

            let _ = event_loop.deregister(&socket);
            let _ = core.remove_state(context);
            let _ = core.remove_context(token);
            let _ = event_tx.send(Event::LostPeer(peer_id));

            return;
        }

        let heartbeat = match Heartbeat::new(core, event_loop, context) {
            Ok(heartbeat) => heartbeat,
            Err(error) => {
                error!("Failed to initialize heartbeat: {:?}", error);

                let _ = event_loop.deregister(&socket);
                let _ = core.remove_state(context);
                let _ = core.remove_context(token);
                let _ = event_tx.send(Event::LostPeer(peer_id));

                return;
            }
        };

        let _ = connection_map.lock().unwrap().insert(peer_id, context);

        let state = ActiveConnection {
            connection_map: connection_map,
            context: context.clone(),
            event_tx: event_tx,
            heartbeat: heartbeat,
            peer_id: peer_id,
            socket: socket,
            token: token,
            event_set: event_set,
        };

        let _ = core.insert_state(context, state);
    }

    fn read(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match self.socket.read::<Message>() {
            Ok(Some(Message::Data(data))) => {
                let _ = self.event_tx.send(Event::NewMessage(self.peer_id, data));
                self.receive_heartbeat(core, event_loop);
            }

            Ok(Some(Message::Heartbeat)) => {
                self.receive_heartbeat(core, event_loop);
            }

            Ok(Some(message)) => {
                warn!("Unexpected message: {:?}", message);
                self.receive_heartbeat(core, event_loop);
            }

            Ok(None) => (),
            Err(error) => {
                error!("Failed to read from socket: {:?}", error);
                self.terminate(core, event_loop);
                return;
            }
        }

        self.reregister(core, event_loop);
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match self.socket.flush() {
            Ok(true) => self.event_set.remove(EventSet::writable()),
            Ok(false) => (),
            Err(error) => {
                error!("Failed to flush socket: {:?}", error);
                self.terminate(core, event_loop);
                return;
            }
        }

        self.reregister(core, event_loop);
    }

    fn reregister(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Err(error) = event_loop.reregister(&self.socket,
                                                  self.token,
                                                  self.event_set,
                                                  PollOpt::edge()) {
            error!("Failed to reregister socket: {:?}", error);
            self.terminate(core, event_loop);
        }
    }

    fn write_message(&mut self,
                     core: &mut Core,
                     event_loop: &mut EventLoop<Core>,
                     message: Message) {
        match self.socket.write(message) {
            Ok(true) => self.event_set.remove(EventSet::writable()),
            Ok(false) => self.event_set.insert(EventSet::writable()),
            Err(error) => {
                error!("Failed to write to socket: {:?}", error);
                self.terminate(core, event_loop);
                return;
            }
        }

        self.reregister(core, event_loop);
    }

    fn receive_heartbeat(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Err(error) = self.heartbeat.receive(event_loop) {
            error!("Failed to process received heartbeat: {:?}", error);
            self.terminate(core, event_loop);
        }
    }
}

impl State for ActiveConnection {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet) {
        assert_eq!(token, self.token);

        if event_set.is_error() || event_set.is_hup() {
            self.terminate(core, event_loop);
        } else {
            if event_set.is_writable() {
                self.write(core, event_loop);
            }

            if event_set.is_readable() {
                self.read(core, event_loop);
            }
        }
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, data: Vec<u8>) {
        self.write_message(core, event_loop, Message::Data(data))
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        self.heartbeat.terminate(core, event_loop);

        if let Err(error) = self.socket.shutdown() {
            error!("Failed to shutdown socket: {:?}", error);
        }

        if let Err(error) = event_loop.deregister(&self.socket) {
            error!("Failed to deregister socket: {:?}", error);
        }

        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);
        let _ = self.connection_map.lock().unwrap().remove(&self.peer_id);

        let _ = self.event_tx.send(Event::LostPeer(self.peer_id));
    }

    fn timeout(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, token: <Core as Handler>::Timeout) {
        match self.heartbeat.timeout(event_loop, token) {
            HeartbeatAction::None => (),
            HeartbeatAction::Send => self.write_message(core, event_loop, Message::Heartbeat),
            HeartbeatAction::Terminate => self.terminate(core, event_loop),
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
    fn new(core: &mut Core, event_loop: &mut EventLoop<Core>, context: Context) -> Result<Self, TimerError> {
        let recv_token = core.get_new_token();
        let recv_timeout = try!(event_loop.timeout_ms(recv_token, HEARTBEAT_PERIOD_MS));
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
        if token == self.recv_token { return HeartbeatAction::Terminate; }
        if token == self.send_token {
            return if let Err(error) = event_loop.timeout_ms(self.send_token, HEARTBEAT_PERIOD_MS) {
                error!("Failed to reschedule heartbeat send timer: {:?}", error);
                HeartbeatAction::Terminate
            } else {
                HeartbeatAction::Send
            };
        }

        HeartbeatAction::None
    }

    fn receive(&mut self, event_loop: &mut EventLoop<Core>) -> Result<(), TimerError> {
        let _ = event_loop.clear_timeout(self.recv_timeout);
        self.recv_timeout = try!(event_loop.timeout_ms(self.recv_token, HEARTBEAT_PERIOD_MS));
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
