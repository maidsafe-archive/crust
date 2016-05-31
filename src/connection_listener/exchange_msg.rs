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
use std::rc::Rc;
use std::cell::RefCell;

use active_connection::ActiveConnection;
use core::{Context, Core, State};
use event::Event;
use message::Message;
use peer_id::{self, PeerId};
use service::SharedConnectionMap;
use socket::Socket;
use sodiumoxide::crypto::box_::PublicKey;

pub const EXCHANGE_MSG_TIMEOUT_MS: u64 = 5_000;

pub struct ExchangeMsg {
    token: Token,
    context: Context,
    name_hash: u64,
    our_pk: PublicKey,
    cm: SharedConnectionMap,
    event_tx: ::CrustEventSender,
    timeout: Timeout,
    socket: Option<Socket>,
    peer_id: Option<PeerId>,
    event: Option<Event>,
}

impl ExchangeMsg {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 socket: Socket,
                 our_pk: PublicKey,
                 name_hash: u64,
                 cm: SharedConnectionMap,
                 event_tx: ::CrustEventSender)
                 -> ::Res<()> {
        let token = core.get_new_token();
        let context = core.get_new_context();

        let event_set = EventSet::error() | EventSet::hup() | EventSet::readable();
        try!(event_loop.register(&socket, token, event_set, PollOpt::edge()));

        let timeout = try!(event_loop.timeout_ms(token, EXCHANGE_MSG_TIMEOUT_MS));

        let _ = core.insert_context(token, context);

        let state = ExchangeMsg {
            token: token,
            context: context,
            name_hash: name_hash,
            our_pk: our_pk,
            cm: cm,
            event_tx: event_tx,
            timeout: timeout,
            socket: Some(socket),
            peer_id: None,
            event: None,
        };

        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));

        Ok(())
    }

    fn receive_request(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match self.socket.as_mut().unwrap().read::<Message>() {
            Ok(Some(Message::BootstrapRequest(peer_pk, name_hash))) => {
                self.handle_bootstrap_request(core, event_loop, peer_pk, name_hash)
            }
            Ok(Some(Message::Connect(peer_pk, name_hash))) => {
                self.handle_connect_request(core, event_loop, peer_pk, name_hash)
            }
            Ok(Some(message)) => {
                warn!("Unexpected message in direct connect: {:?}", message);
                self.terminate(core, event_loop)
            }
            Ok(None) => (),
            Err(e) => {
                warn!("Error in read: {:?}", e);
                self.terminate(core, event_loop)
            }
        }
    }

    fn get_peer_id(&mut self, peer_pk: PublicKey, name_hash: u64) -> Result<PeerId, ()> {
        if self.our_pk == peer_pk {
            warn!("Accepted connection from ourselves");
            return Err(());
        }

        if self.name_hash != name_hash {
            warn!("Incompatible protocol version");
            return Err(());
        }

        Ok(peer_id::new(peer_pk))
    }

    fn handle_connect_request(&mut self,
                              core: &mut Core,
                              event_loop: &mut EventLoop<Core>,
                              peer_pk: PublicKey,
                              name_hash: u64) {
        match self.get_peer_id(peer_pk, name_hash) {
            Ok(peer_id) => self.peer_id = Some(peer_id),
            Err(()) => return self.terminate(core, event_loop),
        }
        self.event = Some(Event::NewPeer(Ok(()), self.peer_id.expect("Logic Error")));
        let our_pk = self.our_pk;
        let name_hash = self.name_hash;
        self.write(core, event_loop, Some(Message::Connect(our_pk, name_hash)));
    }

    fn handle_bootstrap_request(&mut self,
                                core: &mut Core,
                                event_loop: &mut EventLoop<Core>,
                                peer_pk: PublicKey,
                                name_hash: u64) {
        match self.get_peer_id(peer_pk, name_hash) {
            Ok(peer_id) => self.peer_id = Some(peer_id),
            Err(()) => return self.terminate(core, event_loop),
        }
        self.event = Some(Event::BootstrapAccept(self.peer_id.expect("Logic Error")));
        let our_pk = self.our_pk;
        self.write(core, event_loop, Some(Message::BootstrapResponse(our_pk)));
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, msg: Option<Message>) {
        match self.socket.as_mut().unwrap().write_2(event_loop, self.token, msg) {
            Ok(true) => self.transition_to_active(core, event_loop),
            Ok(false) => (),
            Err(e) => {
                warn!("Error in writting: {:?}", e);
                self.terminate(core, event_loop);
            }
        }
    }

    fn transition_to_active(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.context);
        let _ = core.remove_context(self.token);
        let _ = event_loop.clear_timeout(self.timeout);

        let peer_id = self.peer_id.take().expect("Logic Error");

        ActiveConnection::start(core,
                                event_loop,
                                self.token,
                                self.socket.take().expect("Logic Error"),
                                self.cm.clone(),
                                peer_id,
                                self.event_tx.clone());

        let event = self.event.take().expect("Logic Error");
        let _ = self.event_tx.send(event);
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
                self.receive_request(core, event_loop)
            }
            if event_set.is_writable() {
                self.write(core, event_loop, None)
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.context);
        let _ = core.remove_context(self.token);
        let _ = event_loop.clear_timeout(self.timeout);
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
