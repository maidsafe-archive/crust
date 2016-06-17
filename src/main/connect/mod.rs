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

pub use self::connection_candidate::ConnectionCandidate;

mod connection_candidate;
mod exchange_msg;

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::{Rc, Weak};

use common::{Context, Core, NameHash, Socket, State};
use main::{ActiveConnection, ConnectionMap, Event, PeerId, PrivConnectionInfo, PubConnectionInfo};
use mio::tcp::{TcpListener, TcpStream};
use mio::{EventLoop, EventSet, PollOpt, Timeout, Token};
use nat;
use self::exchange_msg::ExchangeMsg;

const TIMEOUT_MS: u64 = 60 * 1000;

pub struct Connect {
    token: Token,
    context: Context,
    timeout: Timeout,
    cm: ConnectionMap,
    our_nh: NameHash,
    our_id: PeerId,
    their_id: PeerId,
    weak: Option<Weak<RefCell<Connect>>>,
    listener: Option<TcpListener>,
    children: HashSet<Context>,
    event_tx: ::CrustEventSender,
}

impl Connect {
    pub fn start(core: &mut Core,
                 el: &mut EventLoop<Core>,
                 our_ci: PrivConnectionInfo,
                 their_ci: PubConnectionInfo,
                 cm: ConnectionMap,
                 our_nh: NameHash,
                 event_tx: ::CrustEventSender)
                 -> ::Res<()> {
        let their_id = their_ci.id;

        if their_ci.listeners.is_empty() && our_ci.tcp_socket.is_none() {
            let _ = event_tx.send(Event::NewPeer(Err(their_id)));
        }

        let token = core.get_new_token();
        let context = core.get_new_context();

        let state = Rc::new(RefCell::new(Connect {
            token: token,
            context: context,
            timeout: try!(el.timeout_ms(token, TIMEOUT_MS)),
            cm: cm,
            our_nh: our_nh,
            our_id: our_ci.id,
            their_id: their_id,
            weak: None,
            listener: None,
            children: HashSet::with_capacity(their_ci.listeners.len()),
            event_tx: event_tx,
        }));

        let weak_self = Rc::downgrade(&state);
        state.borrow_mut().weak = Some(weak_self);

        let mut sockets = their_ci.listeners
            .into_iter()
            .filter_map(|elt| Socket::connect(elt.addr()).ok())
            .collect::<Vec<_>>();

        if let Some(mapped_socket) = our_ci.tcp_socket {
            let their_addrs =
                their_ci.tcp_info.endpoints.into_iter().map(|elt| elt.0).collect::<Vec<_>>();
            if let Ok((listener, nat_sockets)) = nat::get_sockets(mapped_socket,
                                                                  their_addrs.len()) {
                try!(el.register(&listener,
                                 token,
                                 EventSet::readable() | EventSet::error() | EventSet::hup(),
                                 PollOpt::edge()));
                state.borrow_mut().listener = Some(listener);
                sockets.extend(nat_sockets.into_iter()
                    .zip(their_addrs)
                    .filter_map(|elt| TcpStream::connect_stream(elt.0, &elt.1).ok())
                    .map(|elt| Socket::wrap(elt))
                    .collect::<Vec<_>>());
            }
        }

        for socket in sockets {
            state.borrow_mut().exchange_msg(core, el, socket);
        }

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, state);

        Ok(())
    }

    fn exchange_msg(&mut self, core: &mut Core, el: &mut EventLoop<Core>, socket: Socket) {
        let self_weak = self.weak.as_ref().expect("Logic Err").clone();
        let handler = move |core: &mut Core, el: &mut EventLoop<Core>, child, res| {
            if let Some(self_rc) = self_weak.upgrade() {
                self_rc.borrow_mut().handle_exchange_msg(core, el, child, res);
            }
        };

        if let Ok(child) = ExchangeMsg::start(core,
                                              el,
                                              socket,
                                              self.our_id,
                                              self.their_id,
                                              self.our_nh,
                                              self.cm.clone(),
                                              Box::new(handler)) {
            let _ = self.children.insert(child);
        }
    }

    fn accept(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        loop {
            match self.listener.as_ref().unwrap().accept() {
                Ok(Some((socket, _))) => self.exchange_msg(core, el, Socket::wrap(socket)),
                Ok(None) | Err(_) => return,
            }
        }
    }

    fn handle_exchange_msg(&mut self,
                           core: &mut Core,
                           el: &mut EventLoop<Core>,
                           child: Context,
                           res: Option<(Socket, Token)>) {
        let _ = self.children.remove(&child);
        if let Some((socket, token)) = res {
            let self_weak = self.weak.as_ref().expect("Logic Err").clone();
            let handler = move |core: &mut Core, el: &mut EventLoop<Core>, child, res| {
                if let Some(self_rc) = self_weak.upgrade() {
                    self_rc.borrow_mut().handle_connection_candidate(core, el, child, res);
                }
            };

            if let Ok(child) = ConnectionCandidate::start(core,
                                                          el,
                                                          token,
                                                          socket,
                                                          self.cm.clone(),
                                                          self.our_id,
                                                          self.their_id,
                                                          Box::new(handler)) {
                let _ = self.children.insert(child);
            }
        }

        if self.children.is_empty() {
            self.terminate(core, el);
        }
    }

    fn handle_connection_candidate(&mut self,
                                   core: &mut Core,
                                   el: &mut EventLoop<Core>,
                                   child: Context,
                                   res: Option<(Socket, Token)>) {
        let _ = self.children.remove(&child);
        if let Some((socket, token)) = res {
            self.terminate(core, el);
            ActiveConnection::start(core,
                                    el,
                                    token,
                                    socket,
                                    self.cm.clone(),
                                    self.our_id,
                                    self.their_id,
                                    Event::NewPeer(Ok(self.their_id)),
                                    self.event_tx.clone());
        }
    }

    fn terminate_children(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        for context in self.children.drain() {
            let child = match core.get_state(context) {
                Some(state) => state,
                None => continue,
            };

            child.borrow_mut().terminate(core, el);
        }
    }
}

impl State for Connect {
    fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, _: Token, es: EventSet) {
        if !es.is_error() && !es.is_hup() && es.is_readable() {
            self.accept(core, el);
        }
    }

    fn timeout(&mut self, core: &mut Core, el: &mut EventLoop<Core>, _token: Token) {
        debug!("Connect to peer {:?} timed out", self.their_id);
        self.terminate(core, el);
    }

    fn terminate(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        self.terminate_children(core, el);

        if let Some(listener) = self.listener.take() {
            let _ = el.deregister(&listener);
        }
        let _ = el.clear_timeout(self.timeout);
        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);


        if !self.cm.lock().unwrap().contains_key(&self.their_id) {
            let _ = self.event_tx.send(Event::NewPeer(Err(self.their_id)));
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
