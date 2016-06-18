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

use common::{Core, Message, Priority, Socket, State};
use main::{ConnectionId, ConnectionMap, PeerId};
use mio::{EventLoop, EventSet, PollOpt, Token};

pub type Finish = Box<FnMut(&mut Core, &mut EventLoop<Core>, Token, Option<Socket>)>;

pub struct ConnectionCandidate {
    token: Token,
    cm: ConnectionMap,
    socket: Option<Socket>,
    their_id: PeerId,
    msg: Option<(Message, Priority)>,
    finish: Finish,
}

impl ConnectionCandidate {
    pub fn start(core: &mut Core,
                 el: &mut EventLoop<Core>,
                 token: Token,
                 socket: Socket,
                 cm: ConnectionMap,
                 our_id: PeerId,
                 their_id: PeerId,
                 finish: Finish)
                 -> ::Res<Token> {
        if our_id > their_id {
            try!(el.reregister(&socket,
                               token,
                               EventSet::writable() | EventSet::error() | EventSet::hup(),
                               PollOpt::edge()));
        }

        let state = ConnectionCandidate {
            token: token,
            cm: cm,
            socket: Some(socket),
            their_id: their_id,
            msg: Some((Message::ChooseConnection, 0)),
            finish: finish,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(token)
    }

    fn read(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::ChooseConnection)) => self.done(core, el),
            Ok(Some(_)) | Err(_) => self.handle_error(core, el),
            Ok(None) => (),
        }
    }

    fn write(&mut self,
             core: &mut Core,
             el: &mut EventLoop<Core>,
             msg: Option<(Message, Priority)>) {
        let terminate = match self.cm.lock().unwrap().get(&self.their_id) {
            Some(&ConnectionId { active_connection: Some(_), .. }) => true,
            _ => false,
        };
        if terminate {
            return self.handle_error(core, el);
        }

        match self.socket.as_mut().unwrap().write(el, self.token, msg) {
            Ok(true) => self.done(core, el),
            Ok(false) => (),
            Err(_) => self.handle_error(core, el),
        }
    }

    fn done(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.token);
        let token = self.token;
        let socket = self.socket.take().expect("Logic Error");

        (*self.finish)(core, el, token, Some(socket));
    }

    fn handle_error(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        self.terminate(core, el);
        let token = self.token;
        (*self.finish)(core, el, token, None);
    }
}

impl State for ConnectionCandidate {
    fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, es: EventSet) {
        if es.is_error() || es.is_hup() {
            return self.handle_error(core, el);
        }
        if es.is_readable() {
            self.read(core, el);
        }
        if es.is_writable() {
            let msg = self.msg.take();
            self.write(core, el, msg);
        }
    }

    fn terminate(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.token);
        let _ = el.deregister(&self.socket.take().expect("Logic Error"));

        let mut guard = self.cm.lock().unwrap();
        if let Entry::Occupied(mut oe) = guard.entry(self.their_id) {
            oe.get_mut().currently_handshaking -= 1;
            if oe.get().currently_handshaking == 0 && oe.get().active_connection.is_none() {
                let _ = oe.remove();
            }
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
