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

use std::rc::Rc;
use std::any::Any;
use std::cell::RefCell;

use socket::Socket;
use message::Message;
use std::net::SocketAddr;
use peer_id::{self, PeerId};
use core::{Context, Core, State};
use sodiumoxide::crypto::box_::PublicKey;
use mio::{EventLoop, EventSet, PollOpt, Token};

pub type Finish = Box<FnMut(&mut Core,
                            &mut EventLoop<Core>,
                            Context,
                            Result<(Socket, Token, PeerId), SocketAddr>)>;

pub struct TryPeer {
    token: Token,
    context: Context,
    peer: SocketAddr,
    our_pk: PublicKey,
    name_hash: u64,
    socket: Option<Socket>,
    request_sent: bool,
    finish: Finish,
}

impl TryPeer {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 peer: SocketAddr,
                 our_pk: PublicKey,
                 name_hash: u64,
                 finish: Finish)
                 -> ::Res<Context> {
        let socket = try!(Socket::connect(&peer));

        let token = core.get_new_token();
        let context = core.get_new_context();

        let state = TryPeer {
            token: token,
            context: context,
            peer: peer,
            our_pk: our_pk,
            name_hash: name_hash,
            socket: Some(socket),
            request_sent: false,
            finish: finish,
        };

        try!(event_loop.register(state.socket.as_ref().expect("Logic Error"),
                                 token,
                                 EventSet::error() | EventSet::hup() | EventSet::writable(),
                                 PollOpt::edge()));

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));

        Ok(context)
    }

    fn send_bootstrap_request(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let our_pk = self.our_pk.clone();
        let name_hash = self.name_hash;
        self.write(core,
                   event_loop,
                   Some(Message::BootstrapRequest(our_pk, name_hash)));
        self.request_sent = true;
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, msg: Option<Message>) {
        if self.socket.as_mut().unwrap().write_2(event_loop, self.token, msg).is_err() {
            self.handle_error(core, event_loop);
        }
    }

    fn receive_response(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::BootstrapResponse(peer_pk))) => {
                let _ = core.remove_context(self.token);
                let _ = core.remove_state(self.context);
                let context = self.context;
                let data =
                    (self.socket.take().expect("Logic Error"), self.token, peer_id::new(peer_pk));
                (*self.finish)(core, event_loop, context, Ok(data));
            }
            Ok(Some(_)) => self.handle_error(core, event_loop), // Wrong Handshake Message
            Ok(None) => (),
            Err(_) => self.handle_error(core, event_loop),
        }
    }

    fn handle_error(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        self.terminate(core, event_loop);
        let context = self.context;
        let peer = self.peer.clone();
        (*self.finish)(core, event_loop, context, Err(peer));
    }
}

impl State for TryPeer {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet) {
        if event_set.is_error() || event_set.is_hup() {
            self.handle_error(core, event_loop);
        } else {
            if event_set.is_writable() {
                match self.request_sent {
                    true => self.write(core, event_loop, None),
                    false => self.send_bootstrap_request(core, event_loop),
                }
            }
            if event_set.is_readable() {
                self.receive_response(core, event_loop)
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);
        let _ = event_loop.deregister(&self.socket.take().expect("Logic Error"));
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
