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

use config_handler::Config;
use core::{Core, StateHandle};
use error::Error;
use service::SharedConnectionMap;
use super::cache::Cache;
use super::establish_connections::EstablishBootstrapConnections;

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
                 config: &Config,
                 connection_map: SharedConnectionMap,
                 event_tx: ::CrustEventSender) -> Result<StateHandle, Error> {
        let mut contacts = Vec::with_capacity(MAX_CONTACTS_EXPECTED);
        let mut cache = try!(Cache::new(&config.bootstrap_cache_name));

        // Get contacts from bootstrap cache
        contacts.extend(try!(cache.read_file()));

        // Get further contacts from config file - contains seed nodes
        contacts.extend(config.hard_coded_contacts.iter().cloned());

        // TODO: get contacts from the service discovery. As that is an async
        // process, we can transition to the next state only after it finishes.

        let handle = core.get_new_state_handle();

        // TODO: run the following code after ServiceDiscovery finishes.
        try!(EstablishBootstrapConnections::start(core,
                                                  event_loop,
                                                  handle,
                                                  connection_map,
                                                  event_tx,
                                                  contacts));

        Ok(handle)
    }
}
