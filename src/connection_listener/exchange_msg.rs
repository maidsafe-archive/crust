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
use std::time::Duration;

use active_connection::ActiveConnection;
use connect::ConnectionCandidate;
use core::{Core, State, Priority};
use event::Event;
use message::Message;
use mio::{EventLoop, EventSet, PollOpt, Timeout, Token};
use peer_id::{self, PeerId};
use socket::Socket;
use service::{ConnectionId, ConnectionMap};
use sodiumoxide::crypto::box_::PublicKey;

pub const EXCHANGE_MSG_TIMEOUT_MS: u64 = 10 * 60 * 1000;

pub struct ExchangeMsg {
    cm: ConnectionMap,
    event_tx: ::CrustEventSender,
    name_hash: u64,
    next_state: NextState,
    our_pk: PublicKey,
    socket: Option<Socket>,
    timeout: Timeout,
    token: Token,
}

impl ExchangeMsg {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 timeout_ms: Option<u64>,
                 socket: Socket,
                 our_pk: PublicKey,
                 name_hash: u64,
                 cm: ConnectionMap,
                 event_tx: ::CrustEventSender)
                 -> ::Res<()> {
        let token = core.get_new_token();

        let event_set = EventSet::error() | EventSet::hup() | EventSet::readable();
        try!(event_loop.register(&socket, token, event_set, PollOpt::edge()));

        let timeout = try!(event_loop.timeout(token,
                     Duration::from_millis(timeout_ms.unwrap_or(EXCHANGE_MSG_TIMEOUT_MS))));

        let state = ExchangeMsg {
            cm: cm,
            event_tx: event_tx,
            name_hash: name_hash,
            next_state: NextState::None,
            our_pk: our_pk,
            socket: Some(socket),
            timeout: timeout,
            token: token,
        };

        let context = core.get_new_context();
        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));

        Ok(())
    }

    fn read(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::BootstrapRequest(their_public_key, name_hash))) => {
                self.handle_bootstrap_request(core, event_loop, their_public_key, name_hash)
            }
            Ok(Some(Message::Connect(their_public_key, name_hash))) => {
                self.handle_connect(core, event_loop, their_public_key, name_hash)
            }
            Ok(Some(message)) => {
                warn!("Unexpected message in direct connect: {:?}", message);
                self.terminate(core, event_loop)
            }
            Ok(None) => (),
            Err(error) => {
                error!("Failed to read from socket: {:?}", error);
                self.terminate(core, event_loop);
            }
        }
    }

    fn handle_bootstrap_request(&mut self,
                                core: &mut Core,
                                event_loop: &mut EventLoop<Core>,
                                their_public_key: PublicKey,
                                name_hash: u64) {
        let their_id = match self.get_peer_id(their_public_key, name_hash) {
            Ok(their_id) => their_id,
            Err(()) => return self.terminate(core, event_loop),
        };

        let our_pk = self.our_pk;
        self.next_state = NextState::ActiveConnection(their_id);
        self.write(core,
                   event_loop,
                   Some((Message::BootstrapResponse(our_pk), 0)))
    }

    fn handle_connect(&mut self,
                      core: &mut Core,
                      event_loop: &mut EventLoop<Core>,
                      their_public_key: PublicKey,
                      name_hash: u64) {
        let their_id = match self.get_peer_id(their_public_key, name_hash) {
            Ok(their_id) => their_id,
            Err(()) => return self.terminate(core, event_loop),
        };

        let our_pk = self.our_pk;
        let name_hash = self.name_hash;
        self.next_state = NextState::ConnectionCandidate(their_id);
        self.write(core,
                   event_loop,
                   Some((Message::Connect(our_pk, name_hash), 0)));
    }

    fn get_peer_id(&self, their_public_key: PublicKey, name_hash: u64) -> Result<PeerId, ()> {
        if self.our_pk == their_public_key {
            warn!("Accepted connection from ourselves");
            return Err(());
        }

        if self.name_hash != name_hash {
            warn!("Incompatible protocol version");
            return Err(());
        }

        let their_id = peer_id::new(their_public_key);

        {
            let mut guard = self.cm.lock().unwrap();
            guard.entry(their_id)
                .or_insert(ConnectionId {
                    active_connection: None,
                    currently_handshaking: 0,
                })
                .currently_handshaking += 1;
        }

        Ok(their_id)
    }

    fn write(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             msg: Option<(Message, Priority)>) {
        // Do not accept multiple bootstraps from same peer
        if let NextState::ActiveConnection(their_id) = self.next_state {
            let terminate = match self.cm.lock().unwrap().get(&their_id).map(|elt| *elt) {
                Some(ConnectionId { active_connection: Some(_), .. }) => true,
                _ => false,
            };
            if terminate {
                return self.terminate(core, event_loop);
            }
        }

        match self.socket.as_mut().unwrap().write(event_loop, self.token, msg) {
            Ok(true) => self.finish(core, event_loop),
            Ok(false) => (),
            Err(e) => {
                warn!("Error in writting: {:?}", e);
                self.terminate(core, event_loop)
            }
        }
    }

    fn finish(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Some(context) = core.remove_context(self.token) {
            let _ = core.remove_state(context);
        }
        let _ = event_loop.clear_timeout(&self.timeout);

        let our_id = peer_id::new(self.our_pk);

        match self.next_state {
            NextState::ActiveConnection(their_id) => {
                ActiveConnection::start(core,
                                        event_loop,
                                        self.token,
                                        self.socket.take().unwrap(),
                                        self.cm.clone(),
                                        their_id,
                                        our_id,
                                        Event::BootstrapAccept(their_id),
                                        self.event_tx.clone());
            }
            NextState::ConnectionCandidate(their_id) => {
                ConnectionCandidate::start(core,
                                           event_loop,
                                           self.token,
                                           self.socket.take().unwrap(),
                                           self.cm.clone(),
                                           our_id,
                                           their_id,
                                           self.event_tx.clone());
            }
            NextState::None => self.terminate(core, event_loop),
        }
    }
}

impl State for ExchangeMsg {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet) {
        if event_set.is_error() || event_set.is_hup() {
            self.terminate(core, event_loop);
        } else {
            if event_set.is_readable() {
                self.read(core, event_loop)
            }
            if event_set.is_writable() {
                self.write(core, event_loop, None)
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Some(context) = core.remove_context(self.token) {
            let _ = core.remove_state(context);
        }

        match self.next_state {
            NextState::ConnectionCandidate(their_id) |
            NextState::ActiveConnection(their_id) => {
                let mut guard = self.cm.lock().unwrap();
                let remove = {
                    let conn_id = guard.get_mut(&their_id)
                        .expect("ExchangeMsg terminate Logic Error");
                    conn_id.currently_handshaking -= 1;
                    conn_id.currently_handshaking == 0 && conn_id.active_connection.is_none()
                };
                if remove {
                    let _ = guard.remove(&their_id);
                }
            }
            _ => (),
        }

        let _ = event_loop.clear_timeout(&self.timeout);
        let _ = event_loop.deregister(&self.socket.take().expect("Logic Error"));
    }

    fn timeout(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, _token: Token) {
        debug!("Exchange message timed out. Terminating direct connection request.");
        self.terminate(core, event_loop)
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

enum NextState {
    None,
    ActiveConnection(PeerId),
    ConnectionCandidate(PeerId),
}
