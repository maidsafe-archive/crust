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

use common::{Context, Core, Message, NameHash, Priority, Socket, State};
use main::{self, ConnectionId, ConnectionMap, PeerId};
use mio::{EventLoop, EventSet, PollOpt, Token};
use sodiumoxide::crypto::box_::PublicKey;
use std::net::SocketAddr;

pub type Finish = Box<FnMut(&mut Core,
                            &mut EventLoop<Core>,
                            Context,
                            Option<(Socket, Token)>)>;

pub struct ExchangeMsg {
    token: Token,
    context: Context,
    expected_id: PeerId,
    expected_nh: NameHash,
    socket: Option<Socket>,
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
                 -> ::Res<Context> {
        let token = core.get_new_token();
        let context = core.get_new_context();

        try!(el.register(&socket,
                         token,
                         EventSet::error() | EventSet::hup() | EventSet::writable(),
                         PollOpt::edge()));

        {
            let mut guard = cm.lock().unwrap();
            guard.entry(expected_id)
                .or_insert(ConnectionId {
                    active_connection: None,
                    currently_handshaking: 0,
                })
                .currently_handshaking += 1;
        }

        let state = ExchangeMsg {
            token: token,
            context: context,
            expected_id: expected_id,
            expected_nh: name_hash,
            socket: Some(socket),
            cm: cm,
            msg: Some((Message::Connect(our_id.0, name_hash), 0)),
            finish: finish,
        };

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));

        Ok(context)
    }

    fn write(&mut self,
             core: &mut Core,
             el: &mut EventLoop<Core>,
             msg: Option<(Message, Priority)>) {
        if self.socket.as_mut().unwrap().write(el, self.token, msg).is_err() {
            self.handle_error(core, el);
        }
    }

    fn receive_response(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::Connect(their_pk, name_hash))) => {
                if their_pk != self.expected_id.0 || name_hash != self.expected_nh {
                    return self.handle_error(core, el);
                }
                let _ = core.remove_context(self.token);
                let _ = core.remove_state(self.context);
                let token = self.token;
                let context = self.context;
                let socket = self.socket.take().expect("Logic Error");

                (*self.finish)(core, el, context, Some((socket, token)));
            }
            Ok(None) => (),
            Ok(Some(_)) | Err(_) => self.handle_error(core, el),
        }
    }

    fn handle_error(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        self.terminate(core, el);
        let context = self.context;
        (*self.finish)(core, el, context, None);
    }
}

impl State for ExchangeMsg {
    fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, _token: Token, es: EventSet) {
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
        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);
        let _ = el.deregister(&self.socket.take().expect("Logic Error"));
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
