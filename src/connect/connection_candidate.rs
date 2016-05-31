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

use mio::{EventLoop, EventSet, PollOpt, Token};
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use active_connection::ActiveConnection;
use connect::SharedConnectionMap;
use core::{Core, State};
use event::Event;
use message::Message;
use peer_id::PeerId;
use socket::Socket;

pub struct ConnectionCandidate {
    connection_map: SharedConnectionMap,
    event_tx: ::CrustEventSender,
    sent: bool,
    socket: Option<Socket>,
    their_id: PeerId,
    token: Token,
}

impl ConnectionCandidate {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 token: Token,
                 socket: Socket,
                 connection_map: SharedConnectionMap,
                 our_id: PeerId,
                 their_id: PeerId,
                 event_tx: ::CrustEventSender)
    {
        let event_set = EventSet::error() |
                        EventSet::hup() |
                        EventSet::readable();

        let result = if our_id > their_id {
            event_loop.reregister(&socket, token, event_set | EventSet::writable(), PollOpt::edge())
        } else {
            event_loop.reregister(&socket, token, event_set, PollOpt::edge())
        };

        if let Err(error) = result {
            error!("Failed to reregister socket: {:?}", error);
            return;
        }

        let state = ConnectionCandidate {
            connection_map: connection_map,
            event_tx: event_tx,
            sent: false,
            socket: Some(socket),
            their_id: their_id,
            token: token,
        };

        let context = core.get_new_context();
        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));
    }

    fn readable(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::ChooseConnection)) => {
                self.done(core, event_loop)
            }

            Ok(Some(message)) => {
                warn!("Unexpected message: {:?}", message);
                self.terminate(core, event_loop)
            }

            Ok(None) => (),
            Err(error) => {
                error!("Failed to read from socket: {:?}", error);
                self.terminate(core, event_loop)
            }
        }
    }

    fn writable(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if self.connection_exists() {
            self.terminate(core, event_loop);
            return;
        }

        let message = if self.sent {
            None
        } else {
            self.sent = true;
            Some(Message::ChooseConnection)
        };

        match self.socket.as_mut().unwrap().write(event_loop, self.token, message) {
            Ok(true) => self.done(core, event_loop),
            Ok(false) => (),
            Err(error) => {
                error!("Failed to write to socket: {:?}", error);
                self.terminate(core, event_loop);
            }
        }
    }

    fn done(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if self.connection_exists() {
            self.terminate(core, event_loop);
            return;
        }

        if let Some(context) = core.remove_context(self.token) {
            let _ = core.remove_state(context);
        }

        let socket = self.socket.take().unwrap();

        ActiveConnection::start(core,
                                event_loop,
                                self.token,
                                socket,
                                self.connection_map.clone(),
                                self.their_id,
                                self.event_tx.clone());

        let _ = self.event_tx.send(Event::NewPeer(Ok(()), self.their_id));
    }

    fn connection_exists(&self) -> bool {
        self.connection_map.lock().unwrap().contains_key(&self.their_id)
    }
}

impl State for ConnectionCandidate {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet)
    {
        if event_set.is_error() || event_set.is_hup() {
            self.terminate(core, event_loop);
            return;
        }

        if event_set.is_readable() {
            self.readable(core, event_loop);
        }

        if event_set.is_writable() {
            self.writable(core, event_loop);
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Some(socket) = self.socket.take() {
            if let Err(error) = event_loop.deregister(&socket) {
                debug!("Failed to deregister socket: {:?}", error);
            }
        }

        if let Some(context) = core.remove_context(self.token) {
            let _ = core.remove_state(context);
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

