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
use std::rc::Rc;

use active_connection::ActiveConnection;
use connect::SharedConnectionMap;
use core::{Core, State};
use event::Event;
use message::Message;
use mio::{EventLoop, EventSet, Token};
use peer_id::PeerId;
use socket::Socket;

pub struct ConnectionCandidate {
    connection_map: SharedConnectionMap,
    event_tx: ::CrustEventSender,
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
                 event_tx: ::CrustEventSender) {
        let state = Rc::new(RefCell::new(ConnectionCandidate {
            connection_map: connection_map,
            event_tx: event_tx,
            socket: Some(socket),
            their_id: their_id,
            token: token,
        }));

        let context = core.get_new_context();
        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, state.clone());

        if our_id > their_id {
            state.borrow_mut().write(core, event_loop, Some(Message::ChooseConnection));
        }
    }

    fn read(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::ChooseConnection)) => self.finish(core, event_loop),
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

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, msg: Option<Message>) {
        if self.connection_exists() {
            return self.terminate(core, event_loop);
        }

        match self.socket.as_mut().unwrap().write(event_loop, self.token, msg) {
            Ok(true) => self.finish(core, event_loop),
            Ok(false) => (),
            Err(error) => {
                error!("Failed to write to socket: {:?}", error);
                self.terminate(core, event_loop);
            }
        }
    }

    fn finish(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if self.connection_exists() {
            return self.terminate(core, event_loop);
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
             event_set: EventSet) {
        if event_set.is_error() || event_set.is_hup() {
            return self.terminate(core, event_loop);
        }
        if event_set.is_readable() {
            self.read(core, event_loop);
        }
        if event_set.is_writable() {
            self.write(core, event_loop, None);
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
