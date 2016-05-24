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
use sodiumoxide::crypto::sign::PublicKey;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
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
    parent_handle: Context,
    pending_connections: Rc<RefCell<HashSet<Context>>>,
    request_message: Option<Message>,
    socket: Option<Socket>,
    token: Token,
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

        if contact_info.tcp_acceptors.is_empty() {
            warn!("List of TCP acceptors in contact info is empty");
            return;
        }

        let context = core.get_new_context();
        let token = core.get_new_token();
        let _ = core.insert_context(token, context);

        // TODO: try to connect to all the endpoints in the contact info.
        let socket = match Socket::connect(&contact_info.tcp_acceptors[0]) {
            Ok(socket) => socket,
            Err(error) => {
                error!("Failed to connect socket: {:?}", error);
                let _ = core.remove_context(token);
                return;
            }
        };

        let event_set = EventSet::error() |
                        EventSet::hup() |
                        EventSet::readable() |
                        EventSet::writable();

        if let Err(error) = event_loop.register(&socket, token, event_set, PollOpt::edge()) {
            error!("Failed to register socket: {:?}", error);
            let _ = core.remove_context(token);
            return;
        }

        pending_connections.borrow_mut().insert(context);

        let state = EstablishConnection {
            connection_map: connection_map,
            context: context,
            event_tx: event_tx,
            parent_handle: parent_handle,
            pending_connections: pending_connections,
            request_message: Some(Message::BootstrapRequest(our_public_key, name_hash)),
            socket: Some(socket),
            token: token,
        };

        let _ = core.insert_state(context, state);
    }

    fn handle_error(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        self.terminate(core, event_loop);

        // If there are no pending connections left, terminate the whole bootstrap.
        if self.pending_connections.borrow().is_empty() {
            let _ = self.event_tx.send(Event::BootstrapFailed);
            let _ = core.terminate_state(event_loop, self.parent_handle);
        }
    }

    fn send_bootstrap_request(&mut self,
                              core: &mut Core,
                              event_loop: &mut EventLoop<Core>,
                              token: Token) {
        let result = if let Some(message) = self.request_message.take() {
            self.socket.as_mut().unwrap().write(message)
        } else {
            self.socket.as_mut().unwrap().flush()
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
                error!("Failed to flush socket: {:?}", error);
                self.handle_error(core, event_loop);
            }
        }
    }

    fn receive_bootstrap_response(&mut self,
                                  core: &mut Core,
                                  event_loop: &mut EventLoop<Core>,
                                  token: Token)
    {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::BootstrapResponse(public_key))) => {
                self.handle_bootstrap_response(core, event_loop, public_key);
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
                self.handle_error(core, event_loop);
            }
        }
    }

    fn handle_bootstrap_response(&mut self,
                                 core: &mut Core,
                                 event_loop: &mut EventLoop<Core>,
                                 their_public_key: PublicKey) {
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
                                self.socket.take().unwrap(),
                                self.token,
                                self.event_tx.clone())
    }

    fn reregister(&mut self,
                  core: &mut Core,
                  event_loop: &mut EventLoop<Core>,
                  token: Token,
                  writable: bool) {
        let mut event_set = EventSet::error() | EventSet::hup() | EventSet::readable();
        if writable { event_set.insert(EventSet::writable()) }

        if let Err(error) = event_loop.reregister(self.socket.as_ref().unwrap(),
                                                  token,
                                                  event_set,
                                                  PollOpt::edge()) {
            error!("Failed to reregister socket: {:?}", error);
            self.handle_error(core, event_loop);
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
            self.handle_error(core, event_loop);
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

        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);

        if let Some(socket) = self.socket.as_ref() {
            event_loop.deregister(socket).expect("Failed to deregister socket");
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
