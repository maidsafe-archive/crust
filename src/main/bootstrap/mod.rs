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

mod cache;
mod try_peer;

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::mem;
use std::net;
use std::rc::{Rc, Weak};
use std::sync::mpsc::{self, Receiver};

use main::peer_id;
use main::{ActiveConnection, Config, ConnectionMap, CrustError, Event, PeerId};
use common::{Context, Core, Socket, State};
use mio::{EventLoop, Timeout, Token};
use self::cache::Cache;
use self::try_peer::TryPeer;
use service_discovery::ServiceDiscovery;
use sodiumoxide::crypto::box_::PublicKey;
use socket_addr;

const BOOTSTRAP_TIMEOUT_MS: u64 = 10000;
const MAX_CONTACTS_EXPECTED: usize = 1500;
const SERVICE_DISCOVERY_TIMEOUT_MS: u64 = 1000;

pub struct Bootstrap {
    token: Token,
    context: Context,
    cm: ConnectionMap,
    peers: Vec<socket_addr::SocketAddr>,
    blacklist: HashSet<net::SocketAddr>,
    name_hash: u64,
    our_pk: PublicKey,
    event_tx: ::CrustEventSender,
    sd_meta: Option<ServiceDiscMeta>,
    bs_timeout_token: Token,
    bs_timeout: Timeout,
    cache: Cache,
    children: HashSet<Context>,
    self_weak: Option<Weak<RefCell<Bootstrap>>>,
}

impl Bootstrap {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 name_hash: u64,
                 our_pk: PublicKey,
                 cm: ConnectionMap,
                 config: &Config,
                 blacklist: HashSet<net::SocketAddr>,
                 bootstrap_context: Context,
                 service_discovery_context: Context,
                 event_tx: ::CrustEventSender)
                 -> ::Res<()> {
        let mut peers = Vec::with_capacity(MAX_CONTACTS_EXPECTED);

        let mut cache = try!(Cache::new(&config.bootstrap_cache_name));
        peers.extend(cache.read_file());
        peers.extend(config.hard_coded_contacts.clone());

        let token = core.get_new_token();
        let bs_timeout_token = core.get_new_token();
        let bs_timeout = try!(event_loop.timeout_ms(bs_timeout_token, BOOTSTRAP_TIMEOUT_MS));
        let sd_meta = match seek_peers(core, event_loop, service_discovery_context, token) {
            Ok((rx, timeout)) => {
                Some(ServiceDiscMeta {
                    rx: rx,
                    timeout: timeout,
                })
            }
            Err(CrustError::ServiceDiscNotEnabled) => None,
            Err(e) => {
                error!("Failed to seek peers using service discovery: {:?}", e);
                return Err(e);
            }
        };

        let state = Rc::new(RefCell::new(Bootstrap {
            token: token,
            context: bootstrap_context,
            cm: cm,
            peers: peers,
            blacklist: blacklist,
            name_hash: name_hash,
            our_pk: our_pk,
            event_tx: event_tx,
            sd_meta: sd_meta,
            bs_timeout_token: bs_timeout_token,
            bs_timeout: bs_timeout,
            cache: cache,
            children: HashSet::with_capacity(MAX_CONTACTS_EXPECTED),
            self_weak: None,
        }));

        state.borrow_mut().self_weak = Some(Rc::downgrade(&state));

        let _ = core.insert_context(token, bootstrap_context);
        let _ = core.insert_context(bs_timeout_token, bootstrap_context);
        let _ = core.insert_state(bootstrap_context, state.clone());

        if state.borrow().sd_meta.is_none() {
            state.borrow_mut().begin_bootstrap(core, event_loop);
        }

        Ok(())
    }

    fn begin_bootstrap(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let mut peers = mem::replace(&mut self.peers, Vec::new());
        peers.retain(|addr| !self.blacklist.contains(&addr.0));
        if peers.is_empty() {
            let _ = self.event_tx.send(Event::BootstrapFailed);
            return self.terminate(core, event_loop);
        }

        for peer in peers {
            let self_weak = self.self_weak.as_ref().expect("Logic Error").clone();
            let finish = move |core: &mut Core, el: &mut EventLoop<Core>, child_context, res| {
                if let Some(self_rc) = self_weak.upgrade() {
                    self_rc.borrow_mut().handle_result(core, el, child_context, res)
                }
            };

            if let Ok(child) = TryPeer::start(core,
                                              event_loop,
                                              *peer,
                                              self.our_pk,
                                              self.name_hash,
                                              Box::new(finish)) {
                let _ = self.children.insert(child);
            }
        }
    }

    fn handle_result(&mut self,
                     core: &mut Core,
                     event_loop: &mut EventLoop<Core>,
                     child_context: Context,
                     res: Result<(Socket, net::SocketAddr, Token, PeerId), net::SocketAddr>) {
        let _ = self.children.remove(&child_context);
        match res {
            Ok((socket, peer_addr, token, peer_id)) => {
                self.terminate(core, event_loop);
                return ActiveConnection::start(core,
                                               event_loop,
                                               token,
                                               socket,
                                               self.cm.clone(),
                                               peer_id::new(self.our_pk),
                                               peer_id,
                                               Event::BootstrapConnect(peer_id, peer_addr),
                                               self.event_tx.clone());
            }
            Err(bad_peer) => {
                self.cache.remove_peer_acceptor(socket_addr::SocketAddr(bad_peer));
            }
        }

        if self.children.is_empty() {
            self.terminate(core, event_loop);
            let _ = self.event_tx.send(Event::BootstrapFailed);
        }
    }

    fn terminate_children(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        for context in self.children.drain() {
            let child = match core.get_state(context) {
                Some(state) => state,
                None => continue,
            };

            child.borrow_mut().terminate(core, event_loop);
        }
    }
}

impl State for Bootstrap {
    fn timeout(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, token: Token) {
        if token == self.bs_timeout_token {
            let _ = self.event_tx.send(Event::BootstrapFailed);
            return self.terminate(core, event_loop);
        }

        let rx = self.sd_meta.take().expect("Logic Error").rx;

        while let Ok(listeners) = rx.try_recv() {
            self.peers.extend(listeners);
        }

        self.begin_bootstrap(core, event_loop);
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        self.terminate_children(core, event_loop);
        if let Some(sd_meta) = self.sd_meta.take() {
            let _ = event_loop.clear_timeout(sd_meta.timeout);
        }
        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);
        let _ = event_loop.clear_timeout(self.bs_timeout);
        let _ = core.remove_context(self.bs_timeout_token);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

struct ServiceDiscMeta {
    rx: Receiver<Vec<socket_addr::SocketAddr>>,
    timeout: Timeout,
}

fn seek_peers(core: &mut Core,
              event_loop: &mut EventLoop<Core>,
              service_discovery_context: Context,
              token: Token)
              -> ::Res<(Receiver<Vec<socket_addr::SocketAddr>>, Timeout)> {
    if let Some(state) = core.get_state(service_discovery_context) {
        let mut state = state.borrow_mut();
        let mut state = state.as_any()
            .downcast_mut::<ServiceDiscovery>()
            .expect("Cast failure");

        let (obs, rx) = mpsc::channel();
        state.register_observer(obs);
        try!(state.seek_peers());
        let timeout = try!(event_loop.timeout_ms(token, SERVICE_DISCOVERY_TIMEOUT_MS));

        Ok((rx, timeout))
    } else {
        Err(CrustError::ServiceDiscNotEnabled)
    }
}
