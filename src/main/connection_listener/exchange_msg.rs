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
use std::collections::hash_map::Entry;
use std::mem;
use std::rc::Rc;

use common::{self, Core, CoreTimerId, Message, NameHash, Priority, Socket, State};
use main::{ActiveConnection, ConnectionCandidate, ConnectionId, ConnectionMap, Event, PeerId};
use mio::{EventLoop, EventSet, PollOpt, Timeout, Token};
use rust_sodium::crypto::box_::PublicKey;

pub const EXCHANGE_MSG_TIMEOUT_MS: u64 = 10 * 60 * 1000;

pub struct ExchangeMsg {
    token: Token,
    cm: ConnectionMap,
    event_tx: ::CrustEventSender,
    name_hash: u64,
    next_state: NextState,
    our_pk: PublicKey,
    socket: Socket,
    timeout: Timeout,
}

impl ExchangeMsg {
    pub fn start(core: &mut Core,
                 el: &mut EventLoop<Core>,
                 timeout_ms: Option<u64>,
                 socket: Socket,
                 our_pk: PublicKey,
                 name_hash: NameHash,
                 cm: ConnectionMap,
                 event_tx: ::CrustEventSender)
                 -> ::Res<()> {
        let token = core.get_new_token();

        let es = EventSet::error() | EventSet::hup() | EventSet::readable();
        try!(el.register(&socket, token, es, PollOpt::edge()));

        let timeout = try!(el.timeout_ms(CoreTimerId::new(token, 0),
                                         timeout_ms.unwrap_or(EXCHANGE_MSG_TIMEOUT_MS)));

        let state = ExchangeMsg {
            token: token,
            cm: cm,
            event_tx: event_tx,
            name_hash: name_hash,
            next_state: NextState::None,
            our_pk: our_pk,
            socket: socket,
            timeout: timeout,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(())
    }

    fn read(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        match self.socket.read::<Message>() {
            Ok(Some(Message::BootstrapRequest(their_public_key, name_hash))) => {
                self.handle_bootstrap_req(core, el, their_public_key, name_hash)
            }
            Ok(Some(Message::Connect(their_public_key, name_hash))) => {
                self.handle_connect(core, el, their_public_key, name_hash)
            }
            Ok(Some(Message::EchoAddrReq)) => self.handle_echo_addr_req(core, el),
            Ok(Some(message)) => {
                warn!("Unexpected message in direct connect: {:?}", message);
                self.terminate(core, el)
            }
            Ok(None) => (),
            Err(error) => {
                error!("Failed to read from socket: {:?}", error);
                self.terminate(core, el);
            }
        }
    }

    fn handle_bootstrap_req(&mut self,
                            core: &mut Core,
                            el: &mut EventLoop<Core>,
                            their_public_key: PublicKey,
                            name_hash: NameHash) {
        let their_id = match self.get_peer_id(their_public_key, name_hash) {
            Ok(their_id) => their_id,
            Err(()) => return self.terminate(core, el),
        };

        let our_pk = self.our_pk;
        self.next_state = NextState::ActiveConnection(their_id);
        self.write(core, el, Some((Message::BootstrapResponse(our_pk), 0)))
    }

    fn handle_connect(&mut self,
                      core: &mut Core,
                      el: &mut EventLoop<Core>,
                      their_public_key: PublicKey,
                      name_hash: NameHash) {
        let their_id = match self.get_peer_id(their_public_key, name_hash) {
            Ok(their_id) => their_id,
            Err(()) => return self.terminate(core, el),
        };

        let our_pk = self.our_pk;
        let name_hash = self.name_hash;
        self.next_state = NextState::ConnectionCandidate(their_id);
        self.write(core, el, Some((Message::Connect(our_pk, name_hash), 0)));
    }

    fn handle_echo_addr_req(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        self.next_state = NextState::None;
        if let Ok(peer_addr) = self.socket.peer_addr() {
            self.write(core,
                       el,
                       Some((Message::EchoAddrResp(common::SocketAddr(peer_addr)), 0)));
        } else {
            self.terminate(core, el);
        }
    }

    fn get_peer_id(&self, their_public_key: PublicKey, name_hash: NameHash) -> Result<PeerId, ()> {
        if self.our_pk == their_public_key {
            warn!("Accepted connection from ourselves");
            return Err(());
        }

        if self.name_hash != name_hash {
            warn!("Incompatible protocol version");
            return Err(());
        }

        let their_id = PeerId(their_public_key);

        {
            let mut guard = unwrap!(self.cm.lock());
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
             el: &mut EventLoop<Core>,
             msg: Option<(Message, Priority)>) {
        // Do not accept multiple bootstraps from same peer
        if let NextState::ActiveConnection(their_id) = self.next_state {
            let terminate = match unwrap!(self.cm.lock()).get(&their_id).cloned() {
                Some(ConnectionId { active_connection: Some(_), .. }) => true,
                _ => false,
            };
            if terminate {
                return self.terminate(core, el);
            }
        }

        match self.socket.write(el, self.token, msg) {
            Ok(true) => self.done(core, el),
            Ok(false) => (),
            Err(e) => {
                warn!("Error in writting: {:?}", e);
                self.terminate(core, el)
            }
        }
    }

    fn done(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.token);
        let _ = el.clear_timeout(self.timeout);

        let our_id = PeerId(self.our_pk);
        let event_tx = self.event_tx.clone();

        match self.next_state {
            NextState::ActiveConnection(their_id) => {
                let socket = mem::replace(&mut self.socket, Socket::default());
                ActiveConnection::start(core,
                                        el,
                                        self.token,
                                        socket,
                                        self.cm.clone(),
                                        our_id,
                                        their_id,
                                        Event::BootstrapAccept(their_id),
                                        event_tx);
            }
            NextState::ConnectionCandidate(their_id) => {
                let cm = self.cm.clone();
                let handler = move |core: &mut Core, el: &mut EventLoop<Core>, token, res| {
                    if let Some(socket) = res {
                        ActiveConnection::start(core,
                                                el,
                                                token,
                                                socket,
                                                cm.clone(),
                                                our_id,
                                                their_id,
                                                Event::ConnectSuccess(their_id),
                                                event_tx.clone());
                    }
                };

                let socket = mem::replace(&mut self.socket, Socket::default());
                let _ = ConnectionCandidate::start(core,
                                                   el,
                                                   self.token,
                                                   socket,
                                                   self.cm.clone(),
                                                   our_id,
                                                   their_id,
                                                   Box::new(handler));
            }
            NextState::None => self.terminate(core, el),
        }
    }
}

impl State for ExchangeMsg {
    fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, es: EventSet) {
        if es.is_error() || es.is_hup() {
            self.terminate(core, el);
        } else {
            if es.is_readable() {
                self.read(core, el)
            }
            if es.is_writable() {
                self.write(core, el, None)
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.token);

        match self.next_state {
            NextState::ConnectionCandidate(their_id) |
            NextState::ActiveConnection(their_id) => {
                let mut guard = unwrap!(self.cm.lock());
                if let Entry::Occupied(mut oe) = guard.entry(their_id) {
                    oe.get_mut().currently_handshaking -= 1;
                    if oe.get().currently_handshaking == 0 && oe.get().active_connection.is_none() {
                        let _ = oe.remove();
                    }
                }
            }
            NextState::None => (),
        }

        let _ = el.clear_timeout(self.timeout);
        let _ = el.deregister(&self.socket);
    }

    fn timeout(&mut self, core: &mut Core, el: &mut EventLoop<Core>, _timer_id: u8) {
        debug!("Exchange message timed out. Terminating direct connection request.");
        self.terminate(core, el)
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
