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

use mio::{EventLoop, EventSet, PollOpt, Timeout, Token};
use std::any::Any;

use active_connection::ActiveConnection;
use core::{Context, Core, State};
use event::Event;
use message::Message;
use peer_id::{self, PeerId};
use service::SharedConnectionMap;
use socket::Socket;
use sodiumoxide::crypto::box_::PublicKey;

pub const BOOTSTRAP_TIMEOUT_MS: u64 = 5_000;

pub struct AcceptConnection {
    connection_map: SharedConnectionMap,
    event_tx: ::CrustEventSender,
    context: Context,
    name_hash: u64,
    our_public_key: PublicKey,
    socket: Option<Socket>,
    their_peer_id: Option<PeerId>,
    token: Token,
    timeout: Timeout,
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
        let event_set = EventSet::error() | EventSet::hup() | EventSet::readable();

        if let Err(error) = event_loop.register(&socket, token, event_set, PollOpt::edge()) {
            error!("Failed to register socket: {:?}", error);
            return;
        }
        let timeout = match event_loop.timeout_ms(token, BOOTSTRAP_TIMEOUT_MS) {
            Ok(timeout) => timeout,
            Err(error) => {
                error!("Failed to schedule bootstrap timeout: {:?}", error);
                let _ = event_loop.deregister(&socket);
                return;
            }
        };

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
            timeout: timeout,
        };

        let _ = core.insert_state(context, state);
    }

    fn receive_request(&mut self,
                       core: &mut Core,
                       event_loop: &mut EventLoop<Core>,
                       token: Token) {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::BootstrapRequest(public_key, name_hash))) => {
                self.handle_bootstrap_request(core, event_loop, token, public_key, name_hash);
            }

            Ok(Some(Message::Connect(public_key, name_hash))) => {
                self.handle_connect_request(core, event_loop, token, public_key, name_hash);
            }

            Ok(Some(message)) => {
                warn!("Unexpected message: {:?}", message);
                self.reregister(core, event_loop, token, false);
            }

            Ok(None) => {
                debug!("Partial read from socket.");
                self.reregister(core, event_loop, token, false);
            }

            Err(error) => {
                error!("Failed to read from socket: {:?}", error);
                self.terminate(core, event_loop);
            }
        }
    }

    fn validity_check(&mut self,
                      core: &mut Core,
                      event_loop: &mut EventLoop<Core>,
                      their_public_key: &PublicKey,
                      name_hash: u64)
                      -> bool {
        if self.our_public_key == *their_public_key {
            error!("Accepted connection from ourselves");
            self.terminate(core, event_loop);
            return false;
        }

        if self.name_hash != name_hash {
            error!("Incompatible protocol version");
            self.terminate(core, event_loop);
            return false;
        }

        true
    }

    fn handle_connect_request(&mut self,
                              core: &mut Core,
                              event_loop: &mut EventLoop<Core>,
                              _token: Token,
                              their_public_key: PublicKey,
                              name_hash: u64)
    {
        if !self.validity_check(core, event_loop, &their_public_key, name_hash) {
            return;
        }
        let their_peer_id = peer_id::new(their_public_key.clone());
        self.their_peer_id = Some(their_peer_id.clone());
        self.transition_to_active(core, event_loop);
        let _ = self.event_tx.send(Event::NewPeer(Ok(()), their_peer_id));
    }

    fn handle_bootstrap_request(&mut self,
                                core: &mut Core,
                                event_loop: &mut EventLoop<Core>,
                                token: Token,
                                their_public_key: PublicKey,
                                name_hash: u64)
    {
        if !self.validity_check(core, event_loop, &their_public_key, name_hash) {
            return;
        }

        self.their_peer_id = Some(peer_id::new(their_public_key));

        match self.socket.as_mut()
                         .unwrap()
                         .write(Message::BootstrapResponse(self.our_public_key)) {
            Ok(true) => self.transition_to_active(core, event_loop),
            Ok(false) => self.reregister(core, event_loop, token, true),

            Err(error) => {
                error!("Failed writing to socket: {:?}", error);
                self.terminate(core, event_loop);
            }
        }
    }

    fn send_bootstrap_response(&mut self,
                               core: &mut Core,
                               event_loop: &mut EventLoop<Core>,
                               token: Token)
    {
        match self.socket.as_mut().unwrap().flush() {
            Ok(true) => {
                let their_peer_id = self.their_peer_id.clone().take().unwrap();
                self.transition_to_active(core, event_loop);
                let _ = self.event_tx.send(Event::BootstrapAccept(their_peer_id));
            }
            Ok(false) => self.reregister(core, event_loop, token, true),
            Err(error) => {
                error!("Failed to flush socket: {:?}", error);
                self.terminate(core, event_loop);
            }
        }
    }

    fn transition_to_active(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let their_peer_id = self.their_peer_id.take().unwrap();
        ActiveConnection::start(core,
                                event_loop,
                                self.context,
                                self.connection_map.clone(),
                                their_peer_id,
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
            self.terminate(core, event_loop);
        }
    }
}

impl State for AcceptConnection {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet) {

        if event_set.is_error() | event_set.is_hup() {
            self.terminate(core, event_loop);
            return;
        }

        if event_set.is_readable() {
            self.receive_request(core, event_loop, token)
        }

        if event_set.is_writable() {
            self.send_bootstrap_response(core, event_loop, token)
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.context);
        let _ = core.remove_context(self.token);
        let _ = event_loop.clear_timeout(self.timeout);
    }

    fn timeout(&mut self, core: &mut Core, _event_loop: &mut EventLoop<Core>, _token: Token) {
        // TODO: does need to notify routing or just silently drop?
        let _ = core.remove_state(self.context);
        let _ = core.remove_context(self.token);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
