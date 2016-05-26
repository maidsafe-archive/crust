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

use mio::{EventLoop, Timeout, TimerError, Token};
use sodiumoxide::crypto::box_::PublicKey;
use std::any::Any;
use std::mem;
use std::sync::mpsc::{self, Receiver};
use std::rc::Rc;
use std::cell::RefCell;

use config_handler::Config;
use core::{Context, Core, State};
use event::Event;
use service::SharedConnectionMap;
use service_discovery::{ServiceDiscovery, ServiceDiscoveryError};
use static_contact_info::StaticContactInfo;
use super::cache::Cache;
use super::bootstrap::Bootstrap;

const MAX_CONTACTS_EXPECTED: usize = 1500;
const SERVICE_DISCOVERY_TIMEOUT_MS: u64 = 1000;

// Returns the peers from service discovery, cache and config for bootstrapping (not to be held)
pub struct GetBootstrapContacts {
    connection_map: SharedConnectionMap,
    contacts: Vec<StaticContactInfo>,
    context: Context,
    event_tx: ::CrustEventSender,
    name_hash: u64,
    our_public_key: PublicKey,
    service_discovery_rx: Receiver<StaticContactInfo>,
    service_discovery_timeout: Timeout,
    service_discovery_token: Token,
}

impl GetBootstrapContacts {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 bootstrap_context: Context,
                 config: &Config,
                 service_discovery_context: Context,
                 our_public_key: PublicKey,
                 name_hash: u64,
                 connection_map: SharedConnectionMap,
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

        contacts.extend(cached_contacts);

        // Get further contacts from config file - contains seed nodes
        contacts.extend(config.hard_coded_contacts.iter().cloned());

        let token = core.get_new_token();

        // Get contacts from service discovery.
        // If service discovery is enabled, we stay in the GetBootstrapContacts
        // state, wait for the service discovery to retrieve some contacts and
        // only then transition to the Bootstrap state. Otherwise, we spin up
        // the Bootstrap state right away.
        match seek_peers(core, event_loop, service_discovery_context, token) {
            Ok((rx, timeout)) => {
                let state = GetBootstrapContacts {
                    connection_map: connection_map,
                    contacts: contacts,
                    context: bootstrap_context,
                    event_tx: event_tx,
                    name_hash: name_hash,
                    our_public_key: our_public_key,
                    service_discovery_rx: rx,
                    service_discovery_timeout: timeout,
                    service_discovery_token: token,
                };

                let _ = core.insert_context(token, bootstrap_context);
                let _ = core.insert_state(bootstrap_context, Rc::new(RefCell::new(state)));
                return;
            }

            Err(SeekPeersError::NotEnabled) => (),
            Err(error) => {
                error!("Failed to seek peers using service discovery: {:?}", error);
            }
        }

        Bootstrap::start(core,
                         event_loop,
                         bootstrap_context,
                         connection_map,
                         event_tx,
                         contacts,
                         our_public_key,
                         name_hash);
    }
}

impl State for GetBootstrapContacts {
    fn timeout(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, _: Token) {
        let mut contacts = mem::replace(&mut self.contacts, Vec::new());

        // Get contacts from service discovery.
        while let Ok(contact) = self.service_discovery_rx.try_recv() {
            contacts.push(contact);
        }

        Bootstrap::start(core,
                         event_loop,
                         self.context,
                         self.connection_map.clone(),
                         self.event_tx.clone(),
                         contacts,
                         self.our_public_key,
                         self.name_hash);

        let _ = core.remove_context(self.service_discovery_token);
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = event_loop.clear_timeout(self.service_discovery_timeout);
        let _ = core.remove_context(self.service_discovery_token);
        let _ = core.remove_state(self.context);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

fn seek_peers(core: &mut Core,
              event_loop: &mut EventLoop<Core>,
              service_discovery_context: Context,
              token: Token)
              -> Result<(Receiver<StaticContactInfo>, Timeout), SeekPeersError> {
    if let Some(state) = core.get_state(service_discovery_context) {
        let mut state = state.borrow_mut();
        let mut state = state.as_any()
                             .downcast_mut::<ServiceDiscovery>()
                             .expect("Cast failure");

        let (tx, rx) = mpsc::channel();
        state.register_observer(tx);
        try!(state.seek_peers());
        let timeout = try!(event_loop.timeout_ms(token, SERVICE_DISCOVERY_TIMEOUT_MS));

        Ok((rx, timeout))
    } else {
        Err(SeekPeersError::NotEnabled)
    }
}

quick_error! {
    #[derive(Debug)]
    enum SeekPeersError {
        NotEnabled {
            description("Service discovery is not enabled")
        }

        ServiceDiscovery(err: ServiceDiscoveryError) {
            description("Service discovery error")
            from()
        }

        Timer(err: TimerError) {
            description("Timer error")
            from()
        }
    }
}
