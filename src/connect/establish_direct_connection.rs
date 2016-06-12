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

use sodiumoxide::crypto::box_::PublicKey;
use std::any::Any;
use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;

use mio::{EventLoop, EventSet, PollOpt, Token};

use core::{Core, State};
use message::Message;
use socket::Socket;

pub struct EstablishDirectConnection<F> {
    finish: Option<F>,
    name_hash: u64,
    our_public_key: PublicKey,
    sent: bool,
    socket: Option<Socket>,
    token: Token,
}

impl<F> EstablishDirectConnection<F>
    where F: FnOnce(&mut Core, &mut EventLoop<Core>, ::Res<(Token, Socket)>) + Any
{
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 addr: SocketAddr,
                 our_public_key: PublicKey,
                 name_hash: u64,
                 finish: F) {

        let socket = match Socket::connect(&addr) {
            Ok(socket) => socket,
            Err(e) => {
                error!("Failed to connect socket: {:?}", e);
                finish(core, event_loop, Err(e));
                return;
            }
        };

        let token = core.get_new_token();
        let event_set = EventSet::error() | EventSet::hup() | EventSet::writable();
        if let Err(error) = event_loop.register(&socket, token, event_set, PollOpt::edge()) {
            error!("Failed to register socket: {:?}", error);
            let _ = socket.shutdown();
            finish(core, event_loop, Err(From::from(error)));
            return;
        }

        let state = EstablishDirectConnection {
            finish: Some(finish),
            name_hash: name_hash,
            our_public_key: our_public_key,
            sent: false,
            socket: Some(socket),
            token: token,
        };

        let context = core.get_new_context();
        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));
    }

    fn writable(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let message = if self.sent {
            None
        } else {
            self.sent = true;
            Some((Message::Connect(self.our_public_key, self.name_hash), 0))
        };

        if let Err(e) = self.socket.as_mut().unwrap().write(event_loop, self.token, message) {
            error!("Failed to write to socket: {:?}", e);
            self.done(core, event_loop, Err(e));
        }
    }

    fn readable(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::Connect(public_key, name_hash))) => {
                self.handle_connect(core, event_loop, public_key, name_hash);
            }

            Ok(Some(message)) => {
                let error = io::Error::new(io::ErrorKind::Other,
                                           format!("Unexpected message: {:?}", message));
                self.done(core, event_loop, Err(From::from(error)));
            }

            Ok(None) => (),
            Err(e) => {
                error!("Failed to read from socket: {:?}", e);
                self.done(core, event_loop, Err(e));
            }
        }
    }

    fn handle_connect(&mut self,
                      core: &mut Core,
                      event_loop: &mut EventLoop<Core>,
                      their_public_key: PublicKey,
                      name_hash: u64) {
        if name_hash != self.name_hash {
            let error = io::Error::new(io::ErrorKind::Other, "Incompatible protocol version");
            self.done(core, event_loop, Err(From::from(error)));
            return;
        }

        if their_public_key == self.our_public_key {
            let error = io::Error::new(io::ErrorKind::Other, "Connecting to ourselves");
            self.done(core, event_loop, Err(From::from(error)));
            return;
        }

        let token = self.token;
        let socket = self.socket.take().unwrap();
        self.done(core, event_loop, Ok((token, socket)))
    }

    fn done(&mut self,
            core: &mut Core,
            event_loop: &mut EventLoop<Core>,
            result: ::Res<(Token, Socket)>) {
        if let Some(context) = core.remove_context(self.token) {
            let _ = core.remove_state(context);
        }

        if let Some(socket) = self.socket.take() {
            if let Err(error) = event_loop.deregister(&socket) {
                debug!("Failed to deregister socket: {}", error);
            }
        }

        let finish = self.finish.take().unwrap();
        finish(core, event_loop, result);
    }
}

impl<F> State for EstablishDirectConnection<F>
    where F: FnOnce(&mut Core, &mut EventLoop<Core>, ::Res<(Token, Socket)>) + Any
{
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet) {
        if event_set.is_error() {
            let error = match self.socket
                .as_ref()
                .unwrap()
                .take_socket_error() {
                Ok(()) => io::Error::new(io::ErrorKind::Other, "Unknown error"),
                Err(e) => e,
            };

            self.done(core, event_loop, Err(From::from(error)));
        } else if event_set.is_hup() {
            let error = io::Error::new(io::ErrorKind::ConnectionAborted, "Connection aborted");
            self.done(core, event_loop, Err(From::from(error)));
        } else {
            if event_set.is_readable() {
                self.readable(core, event_loop)
            }

            if event_set.is_writable() {
                self.writable(core, event_loop)
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let result = io::Error::new(io::ErrorKind::Other, "Connect cancelled");
        self.done(core, event_loop, Err(From::from(result)));
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
