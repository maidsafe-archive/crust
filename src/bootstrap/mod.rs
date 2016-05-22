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

use itertools::Itertools;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::thread;

use maidsafe_utilities::thread::RaiiThreadJoiner;
use rand;
use rand::Rng;
use service_discovery::ServiceDiscovery;
use nat_traversal::MappingContext;
use sodiumoxide::crypto::box_::PublicKey;

use error::Error;
use config_handler::Config;
use connection::Connection;
use connection;
use static_contact_info::StaticContactInfo;
use event::Event;
use bootstrap_handler::CacheManager;
use peer_id::PeerId;

const MAX_CONTACTS_EXPECTED: usize = 1500;

pub struct RaiiBootstrap {
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
}

impl RaiiBootstrap {
    pub fn new(bootstrap_contacts: Vec<StaticContactInfo>,
               our_public_key: PublicKey,
               event_tx: ::CrustEventSender,
               connection_map: Arc<Mutex<HashMap<PeerId, Context>>>,
               cache_mgr: Arc<Mutex<CacheManager>>,
               mc: Arc<MappingContext>,
               version_hash: u64)
               -> RaiiBootstrap {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let cloned_stop_flag = stop_flag.clone();

        let raii_joiner = RaiiThreadJoiner::new(thread!("RaiiBootstrap", move || {
            RaiiBootstrap::bootstrap(bootstrap_contacts,
                                     our_public_key,
                                     cloned_stop_flag,
                                     event_tx,
                                     connection_map,
                                     cache_mgr,
                                     &mc,
                                     version_hash)
        }));

        RaiiBootstrap {
            stop_flag: stop_flag,
            _raii_joiner: raii_joiner,
        }
    }

    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn bootstrap(mut bootstrap_contacts: Vec<StaticContactInfo>,
                 our_public_key: PublicKey,
                 stop_flag: Arc<AtomicBool>,
                 event_tx: ::CrustEventSender,
                 connection_map: Arc<Mutex<HashMap<PeerId, Context>>>,
                 cache_mgr: Arc<Mutex<CacheManager>>,
                 mapping_context: &MappingContext,
                 version_hash: u64) {
        rand::thread_rng().shuffle(&mut bootstrap_contacts[..]);
        for contact in bootstrap_contacts {
            // Bootstrapping got cancelled.
            // Later check the bootstrap contacts in the background to see if they are still valid

            if stop_flag.load(Ordering::SeqCst) {
                break;
            }

            let res = connection::connect(contact,
                                          heart_beat_timeout,
                                          inactivity_timeout,
                                          our_public_key.clone(),
                                          event_tx.clone(),
                                          connection_map.clone(),
                                          cache_mgr.clone(),
                                          mapping_context,
                                          version_hash);
            match res {
                Ok(()) => (),
                Err(e) => {
                    warn!("Error connecting to bootstrap peer: {}", e);
                }
            };
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
                          cache_mgr: Arc<Mutex<CacheManager>>,
                          config: &Config)
                          -> Result<Vec<StaticContactInfo>, Error> {
    let (seek_peers_tx, seek_peers_rx) = mpsc::channel();
    if service_discovery.register_seek_peer_observer(seek_peers_tx) {
        let _ = service_discovery.seek_peers();
    }

    let mut contacts = Vec::with_capacity(MAX_CONTACTS_EXPECTED);

    // Get contacts from bootstrap cache
    contacts.extend(try!(unwrap_result!(cache_mgr.lock()).read_file()));

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

mod states;

use self::states::Connect;

pub struct Bootstrap {
    token: Token,
    context: Context,
    event_tx: ::CrustEventSender,
    cache_mgr: Arc<Mutex<CacheManager>>,
    child_state_handles: HashSet<Context>,
    connection_map: Arc<Mutex<HashMap<PeerId, Context>>>,
}

impl Bootstrap {
    fn new(core: &mut Core,
           event_loop: &mut EventLoop<Core>,
           peer_candidates: Vec<SocketAddr>,
           bootstrap_handle: Arc<Mutex<Option<Context>>>,
           our_pk: PublicKey,
           event_tx: ::CrustEventSender,
           connection_map: Arc<Mutex<HashMap<PeerId, Context>>>,
           cache_mgr: Arc<Mutex<CacheManager>>,
           version_hash: u64)
           -> Result<(), CrustError> {
        let token = core.get_new_token();
        let context = core.get_new_context();
        *bootstrap_handle.lock().unwrap() = Some(context);

        let bootstrap = Rc::new(RefCell::new(Bootstrap {
            token: token,
            context: context,
            event_tx: event_tx,
            cache_mgr: cache_mgr,
            child_state_handles: HashSet::with_capacity(peer_candidates.len()),
            connection_map: connection_map,
        }));

        let our_pk = Rc::new(our_pk);
        for peer_addr in peer_candidates {
            let self_cloned = bootstrap.clone();
            let cb = move |child_handle, res| {
                self_cloned.borrow_mut().handle_result(child_handle, res)
            };
            let _ = bootstrap.borrow_mut()
                             .child_handles
                             .insert(Connect::new(peer_addr, our_pk.clone(), version_hash, cb));
        }

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, bootstrap);
    }

    fn handle_result(&mut self, child_handle: Context, res: Result<PeerId, SocketAddr>) {
        let _ = self.child_state_handles.remove(&child_handle);
        match res {
            Ok(peer_id) => {
                let _ = self.connection_map.lock().unwrap().insert(peer_id.clone(), child_handle);
                let _ = self.event_tx.send(Event::BootstrapConnect(PeerId(peer_id)));
                self.terminate();
                return;
            }
            Err(bad_peer) => {
                let _ = self.cache_mgr.lock().unwrap().remove_peer_listener(bad_peer);
            }
        }

        if self.child_state_handles.is_empty() {
            let _ = event_tx.send(Event::BootstrapFailed);
        }
    }

    fn terminate_children(&mut self, core: &mut Core) {
        for context in self.child_state_handles.drain() {
            let child_state = match core.get_state(&context) {
                Some(state) => state.clone(),
                None => continue,
            };

            child_state.borrow_mut().terminate(core, event_loop);
        }
    }
}

impl State for Bootstrap {
    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        self.terminate_children(core);
        let _ = core.remove_context(&self.token);
        let _ = core.remove_state(&self.context);
        *self.bootstrap_handle.lock().unwrap() = None;
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
