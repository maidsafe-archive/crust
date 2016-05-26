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

use mio::{EventSet, PollOpt, Token, EventLoop};

use core::{Core, Context, State};
use message::Message;
use peer_id::{self, PeerId};
use socket::{Socket, SocketError};

pub struct EstablishDirectConnection<F> {
    context: Context,
    finish: Option<F>,
    name_hash: u64,
    our_public_key: PublicKey,
    sent: bool,
    socket: Option<Socket>,
    their_id: PeerId,
    token: Token,
    writing: bool,
}

impl<F> EstablishDirectConnection<F>
    where F: FnOnce(&mut Core,
                    &mut EventLoop<Core>,
                    io::Result<(Token, Socket)>) + Any
{
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 addr: SocketAddr,
                 their_id: PeerId,
                 our_public_key: PublicKey,
                 name_hash: u64,
                 finish: F) {
        let token = core.get_new_token();
        let context = core.get_new_context();

        let socket = match Socket::connect(&addr) {
            Ok(socket) => socket,
            Err(SocketError::Io(error)) => {
                error!("Failed to connect socket: {:?}", error);
                finish(core, event_loop, Err(error));
                return;
            }
            Err(SocketError::Serialisation(_)) => unreachable!(),
        };

        let event_set = EventSet::error() | EventSet::hup() | EventSet::writable();
        if let Err(error) = event_loop.register(&socket, token, event_set, PollOpt::edge()) {
            error!("Failed to register socket: {:?}", error);
            let _ = socket.shutdown();
            finish(core, event_loop, Err(error));
            return;
        }

        let state = EstablishDirectConnection {
            context: context,
            finish: Some(finish),
            name_hash: name_hash,
            our_public_key: our_public_key,
            sent: false,
            socket: Some(socket),
            their_id: their_id,
            token: token,
            writing: false,
        };

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));
    }

    fn writable(&mut self,
                core: &mut Core,
                event_loop: &mut EventLoop<Core>)
    {
        let result = if self.writing {
            self.socket.as_mut().unwrap().flush()
        } else {
            self.writing = true;
            self.socket.as_mut()
                       .unwrap()
                       .write(Message::Connect(self.our_public_key, self.name_hash))
        };

        match result {
            Ok(true) => self.handle_connect_sent(core, event_loop),
            Ok(false) => self.reregister(core, event_loop, true),
            Err(error) => {
                error!("Failed to write to socket: {:?}", error);
                self.done(core, event_loop, Err(make_io_error(error)));
                return;
            }
        }
    }

    fn readable(&mut self,
                core: &mut Core,
                event_loop: &mut EventLoop<Core>)
    {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::Connect(public_key, name_hash))) => {
                self.handle_connect_received(core,
                                             event_loop,
                                             public_key,
                                             name_hash)
            }

            Ok(Some(message)) => {
                warn!("Unexpected message: {:?}", message);
                self.reregister(core, event_loop, false)
            }

            Ok(None) => {
                self.reregister(core, event_loop, false)
            }

            Err(error) => {
                error!("Failed to read from socket: {:?}", error);
                self.done(core, event_loop, Err(make_io_error(error)))
            }
        }
    }

    fn handle_connect_received(&mut self,
                               core: &mut Core,
                               event_loop: &mut EventLoop<Core>,
                               their_public_key: PublicKey,
                               name_hash: u64)
    {
        if name_hash != self.name_hash {
            let error = io::Error::new(io::ErrorKind::Other, "Incompatible protocol version");
            self.done(core, event_loop, Err(error));
            return;
        }

        if their_public_key == self.our_public_key {
            let error = io::Error::new(io::ErrorKind::Other, "Connecting to ourselves");
            self.done(core, event_loop, Err(error));
            return;
        }

        if self.our_id() < self.their_id {
            let token = self.token;
            let socket = self.socket.take().unwrap();
            self.done(core, event_loop, Ok((token, socket)))
        } else {
            self.writing = false;
            self.reregister(core, event_loop, true)
        }
    }

    fn handle_connect_sent(&mut self,
                           core: &mut Core,
                           event_loop: &mut EventLoop<Core>)
    {
        if self.our_id() < self.their_id {
            self.reregister(core, event_loop, false)
        } else if self.sent {
            let token = self.token;
            let socket = self.socket.take().unwrap();
            self.done(core, event_loop, Ok((token, socket)))
        } else {
            self.sent = true;
            self.reregister(core, event_loop, false)
        }
    }

    fn reregister(&mut self,
                  core: &mut Core,
                  event_loop: &mut EventLoop<Core>,
                  writable: bool) {
        let mut event_set = EventSet::error() | EventSet::hup() | EventSet::readable();
        if writable {
            event_set.insert(EventSet::writable())
        }

        let result = event_loop.reregister(self.socket.as_ref().unwrap(),
                                           self.token,
                                           event_set,
                                           PollOpt::edge());

        if let Err(error) = result {
            error!("Failed to reregister socket: {:?}", error);
            self.done(core, event_loop, Err(error));
        }
    }

    fn done(&mut self,
            core: &mut Core,
            event_loop: &mut EventLoop<Core>,
            result: io::Result<(Token, Socket)>)
    {
        let _ = core.remove_state(self.context);
        let _ = core.remove_context(self.token);

        if let Some(socket) = self.socket.take() {
            match event_loop.deregister(&socket) {
                Ok(()) => (),
                Err(e) => debug!("Failed to deregister socket: {}", e),
            };
        }

        let finish = self.finish.take().unwrap();
        finish(core, event_loop, result);
    }

    fn our_id(&self) -> PeerId {
        peer_id::new(self.our_public_key)
    }
}

impl<F> State for EstablishDirectConnection<F>
    where F: FnOnce(&mut Core,
                    &mut EventLoop<Core>,
                    io::Result<(Token, Socket)>) + Any
{
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet) {
        if event_set.is_error() {
            let error = match self.socket.as_ref()
                                         .unwrap()
                                         .take_socket_error() {
                Ok(()) => io::Error::new(io::ErrorKind::Other, "Unknown error"),
                Err(e) => e,
            };

            self.done(core, event_loop, Err(error));
        } else if event_set.is_hup() {
            let error = io::Error::new(io::ErrorKind::ConnectionAborted, "Connection aborted");
            self.done(core, event_loop, Err(error));
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
        let result = Err(io::Error::new(io::ErrorKind::Other, "Connect cancelled"));
        self.done(core, event_loop, result);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

fn make_io_error(error: SocketError) -> io::Error {
    match error {
        SocketError::Io(error) => error,
        SocketError::Serialisation(error) => {
            io::Error::new(io::ErrorKind::Other, error)
        }
    }
}
