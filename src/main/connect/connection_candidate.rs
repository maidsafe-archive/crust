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

use common::{Context, Core, Message, Priority, Socket, State};
use main::{ActiveConnection, ConnectionId, ConnectionMap, Event, PeerId};
use mio::{EventLoop, EventSet, Token};

pub struct ConnectionCandidate {
    token: Token,
    context: Context,
    cm: ConnectionMap,
    event_tx: ::CrustEventSender,
    socket: Option<Socket>,
    their_id: PeerId,
    our_id: PeerId,
    notify_err: bool,
}

impl ConnectionCandidate {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 token: Token,
                 socket: Socket,
                 cm: ConnectionMap,
                 our_id: PeerId,
                 their_id: PeerId,
                 notify_err: bool,
                 event_tx: ::CrustEventSender) {
        let context = core.get_new_context();
        let state = Rc::new(RefCell::new(ConnectionCandidate {
            token: token,
            context: context,
            cm: cm,
            event_tx: event_tx,
            socket: Some(socket),
            their_id: their_id,
            our_id: our_id,
            notify_err: notify_err,
        }));

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, state.clone());

        if our_id > their_id {
            state.borrow_mut().write(core, event_loop, Some((Message::ChooseConnection, 0)));
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

    fn write(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             msg: Option<(Message, Priority)>) {
        let terminate = match self.cm.lock().unwrap().get(&self.their_id) {
            Some(&ConnectionId { active_connection: Some(_), .. }) => true,
            _ => false,
        };
        if terminate {
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
        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);

        let socket = self.socket.take().unwrap();

        // ActiveConnection::start(core,
        //                         event_loop,
        //                         self.token,
        //                         socket,
        //                         self.cm.clone(),
        //                         self.their_id,
        //                         self.our_id,
        //                         Event::NewPeer(Ok(()), self.their_id),
        //                         self.event_tx.clone());
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
        let socket = self.socket.take().expect("Logic Error");

        let _ = event_loop.deregister(&socket);
        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);

        {
            let mut guard = self.cm.lock().unwrap();
            let remove = {
                let conn_id = guard.get_mut(&self.their_id).expect("Logic Error");
                conn_id.currently_handshaking -= 1;
                conn_id.currently_handshaking == 0 && conn_id.active_connection.is_none()
            };
            if remove {
                let _ = guard.remove(&self.their_id);
                if self.notify_err {
                    // let _ = self.event_tx.send(Event::FailedPeer(self.their_id));
                }
            }
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
