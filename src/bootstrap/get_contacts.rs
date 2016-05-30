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

use std::mem;
use std::rc::Rc;
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver};

use event::Event;
use error::CrustError;
use super::cache::Cache;
use config_handler::Config;
use super::bootstrap::Bootstrap;
use core::{Context, Core, State};
use service::SharedConnectionMap;
use mio::{EventLoop, Timeout, Token};
use service_discovery::ServiceDiscovery;
use sodiumoxide::crypto::box_::PublicKey;
use static_contact_info::StaticContactInfo;

const MAX_CONTACTS_EXPECTED: usize = 1500;
const SERVICE_DISCOVERY_TIMEOUT_MS: u64 = 1000;

// Returns the peers from service discovery, cache and config for bootstrapping (not to be held)
pub struct Bootstrap {
    token: Token,
    context: Context,
    cm: SharedConnectionMap,
    peer_candidates: Vec<SocketAddr>,
    name_hash: u64,
    our_pk: PublicKey,
    event_tx: ::CrustEventSender,
    sd_meta: Option<ServiceDiscMeta>,
    child_contexts: HashSet<Context>,
}

impl Bootstrap {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 name_hash: u64,
                 our_pk: PublicKey,
                 cm: SharedConnectionMap,
                 config: &Config,
                 bootstrap_context: Context,
                 service_discovery_context: Context,
                 event_tx: ::CrustEventSender) {
        let mut contacts = Vec::with_capacity(MAX_CONTACTS_EXPECTED);
        let mut cache = match Cache::new(&config.bootstrap_cache_name) {
            Ok(cache) => cache,
            Err(error) => {
                error!("Failed to create bootstrap cache: {:?}", error);
                let _ = event_tx.send(Event::BootstrapFailed);
                return;
            }
        };

        // Get contacts from bootstrap cache
        let cached_contacts = match cache.read_file() {
            Ok(contacts) => contacts,
            Err(error) => {
                error!("Failed to load bootstrap cache: {:?}", error);
                let _ = event_tx.send(Event::BootstrapFailed);
                return;
            }
        };

        contacts.extend(cached_contacts_info);

        for it in config.hard_coded_contacts.iter().cloned() {
            contacts.extend(it.tcp_acceptors);
        }

        let token = core.get_new_token();
        let (tx, rx) = mpsc::channel();

        let sd_meta = match seek_peers(core, event_loop, service_discovery_context, token) {
            Ok((rx, timeout)) => {
                Some(ServiceDiscMeta {
                    rx: rx,
                    timeout: timeout,
                })
            }
            Err(CrustError::ServiceDiscNotEnabled) => None,
            Err(error) => {
                error!("Failed to seek peers using service discovery: {:?}", error);
                return;
            }
        };
        let state = Rc::new(RefCell::new(Bootstrap {
            token: token,
            context: bootstrap_context,
            cm: cm,
            peers: contacts,
            name_hash: name_hash,
            our_pk: our_pk,
            event_tx: event_tx,
            sd_meta: sd_meta,
            child_contexts: HashSet::with_capacity(MAX_CONTACTS_EXPECTED),
        }));

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, state.clone());

        if state.borrow().sd_meta.is_none() {
            state.borrow_mut().begin_bootstrap(core, event_loop);
        }
    }

    fn begin_bootstrap(&mut self, core: &mut Core, &event_loop: &mut EventLoop<Core>) {}
}

impl State for Bootstrap {
    fn timeout(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, _: Token) {
        let rx = self.sd_meta().take().expect("Logic Error").rx;
        // Get contacts from service discovery.
        while let Ok(contact) = rx.try_recv() {
            self.contacts.extend(contact.tcp_acceptors);
        }

        self.begin_bootstrap(core, event_loop);
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Some(sd_meta) = self.sd_meta.take() {
            let _ = event_loop.clear_timeout(sd_meta.timeout);
        }
        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

struct ServiceDiscMeta {
    rx: Receiver<StaticContactInfo>,
    timeout: Timeout,
}

fn seek_peers(core: &mut Core,
              event_loop: &mut EventLoop<Core>,
              service_discovery_context: Context,
              obs: Sender<StaticContactInfo>,
              token: Token)
              -> ::Res<Timeout> {
    if let Some(state) = core.get_state(service_discovery_context) {
        let mut state = state.borrow_mut();
        let mut state = state.as_any()
                             .downcast_mut::<ServiceDiscovery>()
                             .expect("Cast failure");

        state.register_observer(obs);
        try!(state.seek_peers());
        let timeout = try!(event_loop.timeout_ms(token, SERVICE_DISCOVERY_TIMEOUT_MS));

        Ok(timeout)
    } else {
        Err(CrustError::ServiceDiscNotEnabled)
    }
}
