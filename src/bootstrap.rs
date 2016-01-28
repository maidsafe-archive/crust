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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use maidsafe_utilities::thread::RaiiThreadJoiner;

pub struct Bootstrap {
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
}

impl Bootstrap {
    pub fn new(service_discovery: &ServiceDiscovery,
               our_contact_info: Arc<Mutex<ContactInfo>>,
               event_tx: ::CrustEventSender)
               -> Bootstrap {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let cloned_stop_flag = stop_flag.clone();

        let (seek_peers_tx, seek_peers_rx) = mpsc::channel();
        if service_discovery.register_seek_peer_observer(seek_peers_tx) {
            let _ = service_discovery.seek_peers();
        }

        let raii_joiner = RaiiThreadJoiner::new(thread!("Bootstrap", move || {
            let contacts =
                match Bootstrap::get_bootstrap_contacts(&unwrap_result!(our_contact_info.lock())
                                                             .pub_key,
                                                        seek_peers_rx) {
                    Ok(contacts) => contacts,
                    Err(err) => {
                        error!("Bootstrap failed: {:?}", err);
                        return;
                    }
                };

            Bootstrap::bootstrap(our_contact_info, contacts, cloned_stop_flag, event_tx);
        }));

        Bootstrap {
            stop_flag: stop_flag,
            _raii_joiner: raii_joiner,
        }
    }

    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn get_bootstrap_contacts(our_pub_key: &PublicKey,
                              seek_peers_rx: Receiver<ContactInfo>)
                              -> Result<Vec<ContactInfo>, Error> {
        let mut contacts = Vec::new();

        // Get contacts from service discovery
        thread::sleep(Duration::from_secs(1));
        while let Ok(contact_info) = seek_peers_rx.try_recv() {
            contacts.push(contact_info);
        }

        // Get further contacts from bootstrap cache
        contacts.extend(try!(FileHandler::new()).read_file().unwrap_or(vec![]));

        // Get further contacts from config file - contains seed nodes
        let config = match read_config_file() {
            Ok(cfg) => cfg,
            Err(e) => {
                debug!("Crust failed to read config file; Error: {:?};", e);
                try!(::config_handler::create_default_config_file());
                Config::make_default()
            }
        };
        contacts.extend(config.hard_coded_contacts);

        contacts = contacts.unique().collect_vec();

        // remove own endpoints
        // Node A is on EP Ea. Node B starts up finds A and populates its bootstrap.cache with Ea.
        // Now A dies and C starts after that on exactly Ea. Since they all share the same
        // bootstrap.cache file (if all Crusts start from same path), C will have EP Ea and also
        // have Ea in the bootstrap.cache so it will try to bootstrap to itself. The following code
        // prevents that.
        // let own_listening_endpoint = self.get_known_external_endpoints();
        // contacts.retain(|c| !own_listening_endpoint.contains(&c));
        contacts.retain(|contact| contact.pub_key != *our_pub_key);

        Ok((contacts))
    }

    fn bootstrap(our_contact_info: Arc<Mutex<ContactInfo>>,
                 bootstrap_contacts: Vec<ContactInfo>,
                 stop_flag: Arc<AtomicBool>,
                 event_tx: ::CrustEventSender) {
        for contact in bootstrap_contacts {
            // Bootstrapping got cancelled.
            // Later check the bootstrap contacts in the background to see if they are still valid
            if stop_flag.load(Ordering::SeqCst) {
                return;
            }

            // 1st try a TCP connect
            // 2nd try a UDP connection (and upgrade to UTP)
            let connect_result = connection::connect(contact, our_contact_info.clone(), event_tx);
            if stop_flag.load(Ordering::SeqCst) {
                return;
            }

            if let Ok(connection) = connect_result {
                let event = Event::NewConnection {
                    their_pub_key: contact.pub_key,
                    connection: Ok(connection),
                };
                let _ = event_tx.send(event);
            }
        }

        let _ = event_tx.send(Event::BootstrapFinished);
    }
}

impl Drop for Bootstrap {
    fn drop(&mut self) {
        self.stop();
    }
}
