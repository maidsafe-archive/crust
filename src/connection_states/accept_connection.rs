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
use std::any::Any;

use core::{Context, Core, State};
use event::Event;
use message::Message;
use peer_id::{self, PeerId};
use service::SharedConnectionMap;
use socket::Socket;
use sodiumoxide::crypto::box_::PublicKey;
use super::active_connection::ActiveConnection;

pub struct AcceptConnection {
    connection_map: SharedConnectionMap,
    event_tx: ::CrustEventSender,
    context: Context,
    name_hash: u64,
    our_public_key: PublicKey,
    socket: Option<Socket>,
    their_peer_id: Option<PeerId>,
    token: Token,
}

impl AcceptConnection {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 socket: Socket,
                 our_public_key: PublicKey,
                 name_hash: u64,
                 connection_map: SharedConnectionMap,
                 event_tx: ::CrustEventSender) {

        let context = core.get_new_context();
        let token = core.get_new_token();

        if let Err(error) = event_loop.register(&socket,
                                                token,
                                                EventSet::error() | EventSet::readable(),
                                                PollOpt::edge()) {
            error!("Failed to register socket: {:?}", error);
            return;
        }

        let _ = core.insert_context(token, context);

        let state = AcceptConnection {
            connection_map: connection_map,
            event_tx: event_tx,
            context: context,
            name_hash: name_hash,
            our_public_key: our_public_key,
            socket: Some(socket),
            their_peer_id: None,
            token: token,
        };

        let _ = core.insert_state(context, state);
    }

    fn handle_bootstrap_request(&mut self,
                                core: &mut Core,
                                event_loop: &mut EventLoop<Core>,
                                token: Token,
                                their_public_key: PublicKey,
                                name_hash: u64)
    {
        if self.our_public_key == their_public_key {
            error!("Accepted connection from ourselves");
            self.stop(core, event_loop);
            return;
        }

        if self.name_hash != name_hash {
            error!("Incompatible protocol version");
            self.stop(core, event_loop);
            return;
        }

        if let Err(error) = self.socket
                                .as_mut()
                                .unwrap()
                                .write(Message::BootstrapResponse(self.our_public_key)) {
            error!("Failed writing to socket: {:?}", error);
            self.stop(core, event_loop);
            return;
        }

        self.their_peer_id = Some(peer_id::new(their_public_key));
        self.set_writable(core, event_loop, token);
    }

    fn handle_bootstrap_response_sent(&mut self,
                                      core: &mut Core,
                                      event_loop: &mut EventLoop<Core>)
    {
        let their_peer_id = self.their_peer_id.take().unwrap();
        let _ = self.event_tx.send(Event::BootstrapAccept(their_peer_id));

        ActiveConnection::start(core,
                                event_loop,
                                self.context,
                                self.connection_map.clone(),
                                their_peer_id,
                                self.socket.take().unwrap(),
                                self.token,
                                self.event_tx.clone())
    }

    fn set_readable(&self, core: &mut Core, event_loop: &mut EventLoop<Core>, token: Token) {
        self.reregister(core, event_loop, token, EventSet::error() | EventSet::readable())
    }

    fn set_writable(&self, core: &mut Core, event_loop: &mut EventLoop<Core>, token: Token) {
        self.reregister(core, event_loop, token, EventSet::error() | EventSet::writable())
    }

    fn reregister(&self,
                  core: &mut Core,
                  event_loop: &mut EventLoop<Core>,
                  token: Token,
                  event_set: EventSet) {
        let socket = self.socket.as_ref().unwrap();

        if let Err(error) = event_loop.reregister(socket,
                                                  token,
                                                  event_set,
                                                  PollOpt::edge()) {
            error!("Failed to reregister socket: {:?}", error);
            self.stop(core, event_loop);
        }
    }

    fn stop(&self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.context);
        let _ = core.remove_context(self.token);

        if let Some(socket) = self.socket.as_ref() {
            event_loop.deregister(socket).expect("Failed to deregister socket");
        }
    }
}

impl State for AcceptConnection {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet)
    {
        if event_set.is_error() {
            self.stop(core, event_loop);
            return;
        }

        if event_set.is_readable() {
            match self.socket.as_mut().unwrap().read::<Message>() {
                Ok(Some(Message::BootstrapRequest(public_key, name_hash))) => {
                    self.handle_bootstrap_request(core,
                                                  event_loop,
                                                  token,
                                                  public_key,
                                                  name_hash);
                }

                Ok(Some(message)) => {
                    warn!("Unexpected message: {:?}", message);
                    self.set_readable(core, event_loop, token);
                }

                Ok(None) => {
                    debug!("Partial read from socket.");
                    self.set_readable(core, event_loop, token);
                },

                Err(error) => {
                    error!("Failed to read from socket: {:?}", error);
                    self.stop(core, event_loop);
                }
            }
        }

        if event_set.is_writable() {
            match self.socket.as_mut().unwrap().flush() {
                Ok(true) => self.handle_bootstrap_response_sent(core, event_loop),
                Ok(false) => self.set_writable(core, event_loop, token),
                Err(error) => {
                    error!("Failed to flush socket: {:?}", error);
                    self.stop(core, event_loop);
                }
            }
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
