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


use common::{Core, Message, NameHash, Priority, Socket, State};
use main::{ConnectionId, ConnectionMap, PeerId};
use mio::{EventLoop, EventSet, PollOpt, Token};
use std::any::Any;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::mem;
use std::rc::Rc;

pub type Finish = Box<FnMut(&mut Core, &mut EventLoop<Core>, Token, Option<Socket>)>;

pub struct ExchangeMsg {
    token: Token,
    expected_id: PeerId,
    expected_nh: NameHash,
    socket: Socket,
    cm: ConnectionMap,
    msg: Option<(Message, Priority)>,
    finish: Finish,
}

impl ExchangeMsg {
    pub fn start(core: &mut Core,
                 el: &mut EventLoop<Core>,
                 socket: Socket,
                 our_id: PeerId,
                 expected_id: PeerId,
                 name_hash: u64,
                 cm: ConnectionMap,
                 finish: Finish)
                 -> ::Res<Token> {
        let token = core.get_new_token();

        try!(el.register(&socket,
                         token,
                         EventSet::error() | EventSet::hup() | EventSet::writable(),
                         PollOpt::edge()));

        {
            let mut guard = unwrap!(cm.lock());
            guard.entry(expected_id)
                .or_insert(ConnectionId {
                    active_connection: None,
                    currently_handshaking: 0,
                })
                .currently_handshaking += 1;
        }

        let state = ExchangeMsg {
            token: token,
            expected_id: expected_id,
            expected_nh: name_hash,
            socket: socket,
            cm: cm,
            msg: Some((Message::Connect(our_id.0, name_hash), 0)),
            finish: finish,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(token)
    }

    fn write(&mut self,
             core: &mut Core,
             el: &mut EventLoop<Core>,
             msg: Option<(Message, Priority)>) {
        if self.socket.write(el, self.token, msg).is_err() {
            self.handle_error(core, el);
        }
    }

    fn receive_response(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        match self.socket.read::<Message>() {
            Ok(Some(Message::Connect(their_pk, name_hash))) => {
                if their_pk != self.expected_id.0 || name_hash != self.expected_nh {
                    return self.handle_error(core, el);
                }
                let _ = core.remove_state(self.token);
                let token = self.token;
                let socket = mem::replace(&mut self.socket, Socket::default());

                (*self.finish)(core, el, token, Some(socket));
            }
            Ok(None) => (),
            Ok(Some(_)) | Err(_) => self.handle_error(core, el),
        }
    }

    fn handle_error(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        self.terminate(core, el);
        let token = self.token;
        (*self.finish)(core, el, token, None);
    }
}

impl State for ExchangeMsg {
    fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, es: EventSet) {
        if es.is_error() || es.is_hup() {
            self.handle_error(core, el);
        } else {
            if es.is_writable() {
                let req = self.msg.take();
                self.write(core, el, req);
            }
            if es.is_readable() {
                self.receive_response(core, el)
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.token);
        let _ = el.deregister(&self.socket);

        let mut guard = unwrap!(self.cm.lock());
        if let Entry::Occupied(mut oe) = guard.entry(self.expected_id) {
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
