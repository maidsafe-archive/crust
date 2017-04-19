// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

mod exchange_msg;

use self::exchange_msg::ExchangeMsg;
use common::{Core, CoreTimer, NameHash, Socket, State, Uid};
use main::{ActiveConnection, ConnectionCandidate, ConnectionMap, CrustError, Event,
           PrivConnectionInfo, PubConnectionInfo};
use mio::{Poll, PollOpt, Ready, Token};
use mio::tcp::{TcpListener, TcpStream};
use mio::timer::Timeout;
use nat;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::{Rc, Weak};
use std::time::Duration;

const TIMEOUT_SEC: u64 = 60;

pub struct Connect<UID: Uid> {
    token: Token,
    timeout: Timeout,
    cm: ConnectionMap<UID>,
    our_nh: NameHash,
    our_id: UID,
    their_id: UID,
    self_weak: Weak<RefCell<Connect<UID>>>,
    listener: Option<TcpListener>,
    children: HashSet<Token>,
    event_tx: ::CrustEventSender<UID>,
}

impl<UID: Uid> Connect<UID> {
    pub fn start(core: &mut Core,
                 poll: &Poll,
                 our_ci: PrivConnectionInfo<UID>,
                 their_ci: PubConnectionInfo<UID>,
                 cm: ConnectionMap<UID>,
                 our_nh: NameHash,
                 event_tx: ::CrustEventSender<UID>)
                 -> ::Res<()> {
        let their_id = their_ci.id;
        let their_direct = their_ci.for_direct;
        let their_hole_punch = their_ci.for_hole_punch;

        if their_direct.is_empty() && their_hole_punch.is_empty() {
            let _ = event_tx.send(Event::ConnectFailure(their_id));
            return Err(CrustError::InsufficientConnectionInfo);
        }

        let token = core.get_new_token();

        let state =
            Rc::new(RefCell::new(Self {
                                     token: token,
                                     timeout: core.set_timeout(Duration::from_secs(TIMEOUT_SEC),
                                                               CoreTimer::new(token, 0))?,
                                     cm: cm,
                                     our_nh: our_nh,
                                     our_id: our_ci.id,
                                     their_id: their_id,
                                     self_weak: Weak::new(),
                                     listener: None,
                                     children: HashSet::with_capacity(their_direct.len() +
                                                                      their_hole_punch.len()),
                                     event_tx: event_tx,
                                 }));

        state.borrow_mut().self_weak = Rc::downgrade(&state);

        let mut sockets = their_direct
            .into_iter()
            .filter_map(|elt| Socket::connect(&elt).ok())
            .collect::<Vec<_>>();

        if let Some(hole_punch_sock) = our_ci.hole_punch_socket {
            if let Ok((listener, nat_sockets)) =
                nat::get_sockets(&hole_punch_sock, their_hole_punch.len()) {
                poll.register(&listener,
                              token,
                              Ready::readable() | Ready::error() | Ready::hup(),
                              PollOpt::edge())?;
                state.borrow_mut().listener = Some(listener);
                sockets.extend(nat_sockets
                                   .into_iter()
                                   .zip(their_hole_punch.into_iter().map(|elt| elt))
                                   .filter_map(|elt| {
                                                   TcpStream::connect_stream(elt.0, &elt.1).ok()
                                               })
                                   .map(Socket::wrap)
                                   .collect::<Vec<_>>());
            }
        }

        for socket in sockets {
            state.borrow_mut().exchange_msg(core, poll, socket);
        }

        let _ = core.insert_state(token, state);

        Ok(())
    }

    fn exchange_msg(&mut self, core: &mut Core, poll: &Poll, socket: Socket) {
        let self_weak = self.self_weak.clone();
        let handler = move |core: &mut Core, poll: &Poll, child, res| if let Some(self_rc) =
            self_weak.upgrade() {
            self_rc
                .borrow_mut()
                .handle_exchange_msg(core, poll, child, res);
        };

        if let Ok(child) = ExchangeMsg::start(core,
                                              poll,
                                              socket,
                                              self.our_id,
                                              self.their_id,
                                              self.our_nh,
                                              self.cm.clone(),
                                              Box::new(handler)) {
            let _ = self.children.insert(child);
        }
        self.maybe_terminate(core, poll);
    }

    fn handle_exchange_msg(&mut self,
                           core: &mut Core,
                           poll: &Poll,
                           child: Token,
                           res: Option<Socket>) {
        let _ = self.children.remove(&child);
        if let Some(socket) = res {
            let self_weak = self.self_weak.clone();
            let handler = move |core: &mut Core, poll: &Poll, child, res| if let Some(self_rc) =
                self_weak.upgrade() {
                self_rc
                    .borrow_mut()
                    .handle_connection_candidate(core, poll, child, res);
            };

            if let Ok(child) = ConnectionCandidate::start(core,
                                                          poll,
                                                          child,
                                                          socket,
                                                          self.cm.clone(),
                                                          self.our_id,
                                                          self.their_id,
                                                          Box::new(handler)) {
                let _ = self.children.insert(child);
            }
        }
        self.maybe_terminate(core, poll);
    }

    fn handle_connection_candidate(&mut self,
                                   core: &mut Core,
                                   poll: &Poll,
                                   child: Token,
                                   res: Option<Socket>) {
        let _ = self.children.remove(&child);
        if let Some(socket) = res {
            self.terminate(core, poll);
            return ActiveConnection::start(core,
                                           poll,
                                           child,
                                           socket,
                                           self.cm.clone(),
                                           self.our_id,
                                           self.their_id,
                                           Event::ConnectSuccess(self.their_id),
                                           self.event_tx.clone());
        }
        self.maybe_terminate(core, poll);
    }

    fn maybe_terminate(&mut self, core: &mut Core, poll: &Poll) {
        if self.children.is_empty() {
            self.terminate(core, poll);
        }
    }

    fn accept(&mut self, core: &mut Core, poll: &Poll) {
        loop {
            match unwrap!(self.listener.as_ref()).accept() {
                Ok((socket, _)) => self.exchange_msg(core, poll, Socket::wrap(socket)),
                Err(_) => return,
            }
        }
    }

    fn terminate_children(&mut self, core: &mut Core, poll: &Poll) {
        for child in self.children.drain() {
            let child = match core.get_state(child) {
                Some(state) => state,
                None => continue,
            };

            child.borrow_mut().terminate(core, poll);
        }
    }
}

impl<UID: Uid> State for Connect<UID> {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if !kind.is_error() && !kind.is_hup() && kind.is_readable() {
            self.accept(core, poll);
        }
    }

    fn timeout(&mut self, core: &mut Core, poll: &Poll, _timer_id: u8) {
        debug!("Connect to peer {:?} timed out", self.their_id);
        self.terminate(core, poll);
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        self.terminate_children(core, poll);

        if let Some(listener) = self.listener.take() {
            let _ = poll.deregister(&listener);
        }
        let _ = core.cancel_timeout(&self.timeout);
        let _ = core.remove_state(self.token);

        if !unwrap!(self.cm.lock()).contains_key(&self.their_id) {
            let _ = self.event_tx.send(Event::ConnectFailure(self.their_id));
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
