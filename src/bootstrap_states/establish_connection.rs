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
use sodiumoxide::crypto::box_::PublicKey;
use std::any::Any;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use active_connection::ActiveConnection;
use event::Event;
use core::{Context, Core, State};
use message::Message;
use peer_id;
use service::SharedConnectionMap;
use socket::Socket;
use static_contact_info::StaticContactInfo;

pub struct EstablishConnection {
    connection_map: SharedConnectionMap,
    context: Context,
    event_tx: ::CrustEventSender,
    name_hash: u64,
    our_public_key: PublicKey,
    parent_handle: Context,
    pending_connections: Rc<RefCell<HashSet<Context>>>,
    pending_requests: HashSet<Token>,
    sockets: HashMap<Token, Socket>,
}

impl EstablishConnection {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 contact_info: StaticContactInfo,
                 our_public_key: PublicKey,
                 name_hash: u64,
                 pending_connections: Rc<RefCell<HashSet<Context>>>,
                 connection_map: SharedConnectionMap,
                 parent_handle: Context,
                 event_tx: ::CrustEventSender) {

        let context = core.get_new_context();
        let event_set = EventSet::error() |
                        EventSet::hup() |
                        EventSet::readable() |
                        EventSet::writable();

        let mut sockets = HashMap::new();
        let mut pending_requests = HashSet::new();

        for address in contact_info.tcp_acceptors {
            let socket = match Socket::connect(&address) {
                Ok(socket) => socket,
                Err(error) => {
                    error!("Failed to connect socket: {:?}", error);
                    continue;
                }
            };

            let token = core.get_new_token();

            if let Err(error) = event_loop.register(&socket, token, event_set, PollOpt::edge()) {
                error!("Failed to register socket: {:?}", error);
                let _ = socket.shutdown();
            }

            let _ = core.insert_context(token, context);
            let _ = sockets.insert(token, socket);
            let _ = pending_requests.insert(token);
        }

        if sockets.is_empty() {
            warn!("Failed to connect to any endpoint in this contact");
            return;
        }

        pending_connections.borrow_mut().insert(context);

        let state = EstablishConnection {
            connection_map: connection_map,
            context: context,
            event_tx: event_tx,
            name_hash: name_hash,
            our_public_key: our_public_key,
            parent_handle: parent_handle,
            pending_connections: pending_connections,
            pending_requests: pending_requests,
            sockets: sockets,
        };

        let _ = core.insert_state(context, state);
    }

    fn handle_error(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, token: Token) {
        if let Some(socket) = self.sockets.remove(&token) {
            Self::shutdown_socket(core, event_loop, token, socket);
        }

        if self.sockets.is_empty() {
            self.terminate(core, event_loop);

            // If there are no pending connections left, terminate the whole bootstrap.
            if self.pending_connections.borrow().is_empty() {
                let _ = self.event_tx.send(Event::BootstrapFailed);
                let _ = core.terminate_state(event_loop, self.parent_handle);
            }
        }
    }

    fn send_bootstrap_request(&mut self,
                              core: &mut Core,
                              event_loop: &mut EventLoop<Core>,
                              token: Token) {
        let result = {
            let socket = match self.sockets.get_mut(&token) {
                Some(socket) => socket,
                None => return,
            };

            if self.pending_requests.remove(&token) {
                socket.write(Message::BootstrapRequest(self.our_public_key,
                                                       self.name_hash))
            } else {
                socket.flush()
            }
        };

        match result {
            Ok(true) => {
                // BootstrapRequest sent, start awaiting response.
                self.reregister(core, event_loop, token, false);
            }
            Ok(false) => {
                // More data remain to be sent, stay in the writing mode.
                self.reregister(core, event_loop, token, true);
            }
            Err(error) => {
                error!("Failed to write to socket: {:?}", error);
                self.handle_error(core, event_loop, token);
            }
        }
    }

    fn receive_bootstrap_response(&mut self,
                                  core: &mut Core,
                                  event_loop: &mut EventLoop<Core>,
                                  token: Token)
    {
        match self.sockets.get_mut(&token).unwrap().read::<Message>() {
            Ok(Some(Message::BootstrapResponse(public_key))) => {
                self.handle_bootstrap_response(core, event_loop, token, public_key);
            }

            Ok(Some(message)) => {
                warn!("Unexpected message: {:?}", message);
                // TODO: maybe resend the handshake again here?
                self.reregister(core, event_loop, token, false);
            }

            Ok(None) => {
                self.reregister(core, event_loop, token, false);
            },

            Err(error) => {
                error!("Failed to read from socket: {:?}", error);
                self.handle_error(core, event_loop, token);
            }
        }
    }

    fn handle_bootstrap_response(&mut self,
                                 core: &mut Core,
                                 event_loop: &mut EventLoop<Core>,
                                 token: Token,
                                 their_public_key: PublicKey) {
        // Get the first socket we received bootstrap response on, and shut the
        // others down.
        let socket = self.sockets.remove(&token).unwrap();

        for (token, socket) in self.sockets.drain() {
            Self::shutdown_socket(core, event_loop, token, socket);
        }

        let peer_id = peer_id::new(their_public_key);
        let _ = self.pending_connections.borrow_mut().remove(&self.context);

        // We have a connection, we can terminate the bootstrap now.
        let _ = core.terminate_state(event_loop, self.parent_handle);
        let _ = self.event_tx.send(Event::BootstrapConnect(peer_id));

        ActiveConnection::start(core,
                                event_loop,
                                self.context,
                                self.connection_map.clone(),
                                peer_id,
                                socket,
                                token,
                                self.event_tx.clone())
    }

    fn reregister(&mut self,
                  core: &mut Core,
                  event_loop: &mut EventLoop<Core>,
                  token: Token,
                  writable: bool) {
        let mut event_set = EventSet::error() | EventSet::hup() | EventSet::readable();
        if writable { event_set.insert(EventSet::writable()) }

        let result = {
            let socket = self.sockets.get(&token).unwrap();
            event_loop.reregister(socket, token, event_set, PollOpt::edge())
        };

        if let Err(error) = result {
            error!("Failed to reregister socket: {:?}", error);
            self.handle_error(core, event_loop, token);
        }
    }

    fn shutdown_socket(core: &mut Core,
                       event_loop: &mut EventLoop<Core>,
                       token: Token,
                       socket: Socket) {
        let _ = core.remove_context(token);

        if let Err(error) = event_loop.deregister(&socket) {
            error!("Failed to deregister socket: {:?}", error);
        }

        if let Err(error) = socket.shutdown() {
            error!("Failed to shutdown socket: {:?}", error);
        }
    }
}

impl State for EstablishConnection {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet)
    {
        if event_set.is_error() || event_set.is_hup() {
            self.handle_error(core, event_loop, token);
            return;
        }

        if event_set.is_writable() {
            self.send_bootstrap_request(core, event_loop, token)
        }

        if event_set.is_readable() {
            self.receive_bootstrap_response(core, event_loop, token)
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = self.pending_connections.borrow_mut().remove(&self.context);

        for (token, socket) in self.sockets.drain() {
            Self::shutdown_socket(core, event_loop, token, socket);
        }

        let _ = core.remove_state(self.context);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
