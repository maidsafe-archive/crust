// Copyright 2015 MaidSafe.net limited.
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

// TODO Have facilities to add and remove bootstrap contacts

use itertools::Itertools;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::thread;

use config_file_handler::FileHandler;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use rand;
use rand::Rng;
use service_discovery::ServiceDiscovery;
use nat_traversal::MappingContext;
use sodiumoxide::crypto::box_::PublicKey;

use error::Error;
use config_handler::Config;
use connection::Connection;
use static_contact_info::StaticContactInfo;
use event::Event;
use bootstrap_handler::BootstrapHandler;
use peer_id;
use peer_id::PeerId;

const MAX_CONTACTS_EXPECTED: usize = 1500;

pub struct RaiiBootstrap {
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
}

impl RaiiBootstrap {
    pub fn new(our_contact_info: Arc<Mutex<StaticContactInfo>>,
               peer_contact_infos: Arc<Mutex<Vec<StaticContactInfo>>>,
               our_public_key: PublicKey,
               event_tx: ::CrustEventSender,
               connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>,
               bootstrap_cache: Arc<Mutex<BootstrapHandler>>,
               mc: Arc<MappingContext>)
               -> RaiiBootstrap {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let cloned_stop_flag = stop_flag.clone();

        let raii_joiner = RaiiThreadJoiner::new(thread!("RaiiBootstrap", move || {
            RaiiBootstrap::bootstrap(our_contact_info,
                                     peer_contact_infos,
                                     our_public_key,
                                     cloned_stop_flag,
                                     event_tx,
                                     connection_map,
                                     bootstrap_cache,
                                     &mc);
        }));

        RaiiBootstrap {
            stop_flag: stop_flag,
            _raii_joiner: raii_joiner,
        }
    }

    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn bootstrap(our_contact_info: Arc<Mutex<StaticContactInfo>>,
                 peer_contact_infos: Arc<Mutex<Vec<StaticContactInfo>>>,
                 our_public_key: PublicKey,
                 stop_flag: Arc<AtomicBool>,
                 event_tx: ::CrustEventSender,
                 connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>,
                 bootstrap_cache: Arc<Mutex<BootstrapHandler>>,
                 mapping_context: &MappingContext) {
        let mut bootstrap_contacts: Vec<StaticContactInfo> =
            unwrap_result!(peer_contact_infos.lock()).clone();
        rand::thread_rng().shuffle(&mut bootstrap_contacts[..]);
        for contact in bootstrap_contacts {
            // Bootstrapping got cancelled.
            // Later check the bootstrap contacts in the background to see if they are still valid

            if stop_flag.load(Ordering::SeqCst) {
                break;
            }

            // 1st try a TCP connect
            // 2nd try a UDP connection (and upgrade to UTP)
            let _ = ::connection::connect(contact,
                                          our_contact_info.clone(),
                                          our_public_key.clone(),
                                          event_tx.clone(),
                                          connection_map.clone(),
                                          bootstrap_cache.clone(),
                                          mapping_context);
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
        }

        let _ = event_tx.send(Event::BootstrapFinished);
    }
}

impl Drop for RaiiBootstrap {
    fn drop(&mut self) {
        self.stop();
    }
}

// Returns the peers from service discovery, cache and config for bootstrapping (not to be held)
pub fn get_known_contacts(service_discovery: &ServiceDiscovery<StaticContactInfo>,
                          bootstrap_cache: Arc<Mutex<BootstrapHandler>>,
                          config: &Config)
                          -> Result<Vec<StaticContactInfo>, Error> {
    let (seek_peers_tx, seek_peers_rx) = mpsc::channel();
    if service_discovery.register_seek_peer_observer(seek_peers_tx) {
        let _ = service_discovery.seek_peers();
    }

    let mut contacts = Vec::with_capacity(MAX_CONTACTS_EXPECTED);

    // Get contacts from bootstrap cache
    contacts.extend(try!(unwrap_result!(bootstrap_cache.lock()).read_file()));

    // Get further contacts from config file - contains seed nodes
    contacts.extend(config.hard_coded_contacts.iter().cloned());

    // Get contacts from service discovery. Give a sec or so for seek peers to find someone on LAN.
    thread::sleep(Duration::from_secs(1));
    while let Ok(static_contact_info) = seek_peers_rx.try_recv() {
        contacts.push(static_contact_info);
    }

    // Please don't be tempted to use a HashSet here because we want to preserve the
    // order in which we collect the contacts
    contacts = contacts.into_iter().unique().collect();


    Ok((contacts))
}

