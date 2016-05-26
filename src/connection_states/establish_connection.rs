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
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use active_connection::ActiveConnection;
use core::{Core, Context, State};
use event::Event;
use message::Message;
use mio::{PollOpt, Token, EventLoop, EventSet};
use peer_id::{self, PeerId};
use socket::Socket;
use sodiumoxide::crypto::box_::PublicKey;
use static_contact_info::StaticContactInfo;

pub struct EstablishConnection {
    connection_map: Arc<Mutex<HashMap<PeerId, Context>>>,
    context: Context,
    name_hash: u64,
    our_public_key: PublicKey,
    routing_tx: ::CrustEventSender,
    socket: Option<Socket>, // Allows moving out without needing to clone the stream
    token: Token,
}

impl EstablishConnection {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 peer_contact_info: StaticContactInfo,
                 connection_map: Arc<Mutex<HashMap<PeerId, Context>>>,
                 routing_tx: ::CrustEventSender,
                 our_public_key: PublicKey,
                 name_hash: u64) {
        debug!("Entered state EstablishConnection");

        let context = core.get_new_context();
        let socket = Socket::connect(&peer_contact_info.tcp_acceptors[0]).expect("Could not connect to peer");
        let token = core.get_new_token();
        let connection = EstablishConnection {
            connection_map: connection_map,
            name_hash: name_hash,
            our_public_key: our_public_key,
            context: context.clone(),
            routing_tx: routing_tx,
            socket: Some(socket),
            token: token,
        };

        event_loop.register(connection.socket.as_ref().expect("Logic Error"),
                            token,
                            EventSet::error() | EventSet::writable(),
                            PollOpt::edge())
                  .expect("Could not register socket with EventLoop<Core>");

        let _ = core.insert_context(token, context.clone());
        let _ = core.insert_state(context, connection);
    }

    fn send_bootstrap_request(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let result = {
            self.socket.as_mut().expect("Logic Error")
                       .write(Message::BootstrapRequest(self.our_public_key,
                                                        self.name_hash))
        };

        match result {
            Ok(true) => {
                // BootstrapRequest sent, start awaiting response.
                self.reregister(core, event_loop, false);
            }
            Ok(false) => {
                // More data remain to be sent, stay in the writing mode.
                self.reregister(core, event_loop, true);
            }
            Err(error) => {
                error!("Failed to write to socket: {:?}", error);
                self.shutdown(core, event_loop);
            }
        }
    }

    fn receive_bootstrap_response(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match self.socket.as_mut().expect("Logic Error").read::<Message>() {
            Ok(Some(Message::BootstrapResponse(public_key))) => {
                self.handle_bootstrap_response(core, event_loop, public_key);
            }
            Ok(Some(message)) => {
                warn!("Unexpected message: {:?}", message);
                // TODO: maybe resend the handshake again here?
                self.reregister(core, event_loop, false);
            }
            Ok(None) => self.reregister(core, event_loop, false),
            Err(error) => {
                error!("Failed to read from socket: {:?}", error);
                self.shutdown(core, event_loop);
            }
        }
    }

    fn handle_bootstrap_response(&mut self,
                                 core: &mut Core,
                                 event_loop: &mut EventLoop<Core>,
                                 their_public_key: PublicKey) {
        self.shutdown(core, event_loop);
        let peer_id = peer_id::new(their_public_key);
        let _ = self.routing_tx.send(Event::BootstrapConnect(peer_id));
        ActiveConnection::start(core,
                                event_loop,
                                self.context,
                                self.connection_map.clone(),
                                peer_id,
                                self.socket.take().expect("Logic Error"),
                                self.token,
                                self.routing_tx.clone())
    }

    fn reregister(&mut self,
                  core: &mut Core,
                  event_loop: &mut EventLoop<Core>,
                  writable: bool) {
        let mut event_set = EventSet::error() | EventSet::hup() | EventSet::readable();
        if writable { event_set.insert(EventSet::writable()) }

        let result = {
            event_loop.reregister(self.socket.as_ref().expect("Logic Error"),
                                  self.token, event_set, PollOpt::edge())
        };

        if let Err(error) = result {
            error!("Failed to reregister socket: {:?}", error);
            self.shutdown(core, event_loop);
        }
    }

    fn shutdown(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.context);
        let _ = core.remove_context(self.token);
        if let Err(error) = event_loop.deregister(self.socket.as_ref().expect("Logic Error")) {
            error!("Failed to deregister socket: {:?}", error);
        }
    }
}

impl State for EstablishConnection {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet) {
        if event_set.is_error() || event_set.is_hup() {
            self.shutdown(core, event_loop);
            return;
        }

        if event_set.is_writable() {
            self.send_bootstrap_request(core, event_loop)
        }

        if event_set.is_readable() {
            self.receive_bootstrap_response(core, event_loop)
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
