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

use mio::{Token, EventLoop, EventSet, PollOpt};
use std::any::Any;
use std::io::{Read, Write};

use core::{Core, Context, State};
use event::Event;
use message::Message;
use peer_id::PeerId;
use service::SharedConnectionMap;
use socket::Socket;

pub struct ActiveConnection {
    connection_map: SharedConnectionMap,
    context: Context,
    event_tx: ::CrustEventSender,
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

        let _ = connection_map.lock().unwrap().insert(peer_id, context);

        let state = ActiveConnection {
            connection_map: connection_map,
            context: context.clone(),
            event_tx: event_tx,
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
            }

            Ok(Some(message)) => warn!("Unexpected message: {:?}", message),
            Ok(None) => (),
            Err(error) => {
                error!("Failed to read from socket: {:?}", error);
                self.stop(core, event_loop);
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
                self.stop(core, event_loop);
                return;
            }
        }

        self.reregister(core, event_loop);
    }

    fn stop(&self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
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

    fn reregister(&self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Err(error) = event_loop.reregister(&self.socket,
                                                  self.token,
                                                  self.event_set,
                                                  PollOpt::edge()) {
            error!("Failed to reregister socket: {:?}", error);
            self.stop(core, event_loop);
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

        if event_set.is_error() {
            self.stop(core, event_loop);
            return;
        }

        if event_set.is_writable() {
            self.write(core, event_loop);
        }

        if event_set.is_readable() {
            self.read(core, event_loop);
        }

        if event_set.is_hup() {
            self.stop(core, event_loop);
        }
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, data: Vec<u8>) {
        if let Err(error) = self.socket.write(Message::Data(data)) {
            error!("Failed to write to socket: {:?}", error);
            self.stop(core, event_loop);
            return;
        }

        self.event_set.insert(EventSet::writable());
        self.reregister(core, event_loop);
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        self.stop(core, event_loop);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
