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

use mio::EventLoop;
use sodiumoxide::crypto::sign::PublicKey;

use config_handler::Config;
use core::{Context, Core};
use event::Event;
use service::SharedConnectionMap;
use super::cache::Cache;
use super::bootstrap::Bootstrap;

const MAX_CONTACTS_EXPECTED: usize = 1500;

// Returns the peers from service discovery, cache and config for bootstrapping (not to be held)
pub struct GetBootstrapContacts {

    // TODO: uncomment this when we add ServiceDiscovery, as we would need to
    // keep the contacts around until it finishes.
    // // Please don't be tempted to use a HashSet here because we want to preserve the
    // // order in which we collect the contacts
    // contacts: Vec<StaticContactInfo>,
}

impl GetBootstrapContacts {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 context: Context,
                 config: &Config,
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

        // TODO: get contacts from the service discovery. As that is an async
        // process, we can transition to the next state only after it finishes.

        // TODO: run the following code after ServiceDiscovery finishes.
        Bootstrap::start(core,
                         event_loop,
                         context,
                         connection_map,
                         event_tx,
                         contacts,
                         our_public_key,
                         name_hash)
    }
}
