// Copyright 2017 MaidSafe.net limited.
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

use common::{Core, CoreMessage, CrustUser, FakePoll, Uid};
use maidsafe_utilities;
use main::{ActiveConnection, ConfigFile, ConnectionMap};
use notify::{self, DebouncedEvent, Watcher};
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

const MAGIC_SHUTDOWN_MSG: &str = "crust shutdown";

pub struct ConfigRefresher {
    tx: Sender<DebouncedEvent>,
    _handle: maidsafe_utilities::thread::Joiner,
}

impl ConfigRefresher {
    pub fn start<UID: Uid>(
        core: &mut Core,
        cm: ConnectionMap<UID>,
        config: ConfigFile,
    ) -> ::Res<ConfigRefresher> {
        trace!("Entered state ConfigRefresher");

        let sender = core.sender().clone();

        let (tx, rx) = mpsc::channel();
        let tx_cloned = tx.clone();
        let mut watcher = notify::watcher(tx_cloned, Duration::new(1, 0))?;
        watcher.watch(
            &config.get_file_path()?,
            notify::RecursiveMode::NonRecursive,
        )?;
        let handle = maidsafe_utilities::thread::named("Config file watcher", move || {
            for event in rx {
                if let DebouncedEvent::Error(e, _) = event {
                    if let notify::Error::Generic(ref msg) = e {
                        if msg == MAGIC_SHUTDOWN_MSG {
                            return;
                        }
                    }
                    warn!("file system watcher raised an error: {}", e);
                };
                let config_cloned = config.clone();
                let cm_cloned = cm.clone();
                let send_result = sender.send(CoreMessage::new(move |core, poll| {
                    ConfigRefresher::refresh_config(core, poll, config_cloned, &cm_cloned)
                }));
                if send_result.is_err() {
                    return;
                }
            }
            drop(watcher);
        });

        let ret = ConfigRefresher {
            tx: tx,
            _handle: handle,
        };

        Ok(ret)
    }

    fn refresh_config<UID: Uid>(
        core: &mut Core,
        poll: &FakePoll,
        config: ConfigFile,
        cm: &ConnectionMap<UID>,
    ) {
        match config.reload() {
            Ok(()) => (),
            Err(e) => {
                debug!(
                    "Could not read Crust config (it's rescheduled to be read): {:?}",
                    e
                );
            }
        };

        let config = config.read();
        let whitelisted_node_ips = config.whitelisted_node_ips.clone();
        let whitelisted_client_ips = config.whitelisted_client_ips.clone();

        if whitelisted_node_ips.is_none() && whitelisted_client_ips.is_none() {
            return;
        }

        trace!(
            "Crust config has been updated - going to purge any nodes or clients that are no \
               longer whitelisted"
        );

        // Peers collected to avoid keeping the mutex lock alive which might lead to deadlock
        let peers_to_terminate: Vec<_> =
            unwrap!(cm.lock())
                .values()
                .filter_map(|cid| {
                    cid.active_connection.and_then(|token| core.get_state(token)).and_then(|peer| {
                    let should_drop = {
                        let mut state = peer.borrow_mut();
                        let ac = match state.as_any().downcast_mut::<ActiveConnection<UID>>() {
                            Some(ac) => ac,
                            None => {
                                warn!("Token reserved for ActiveConnection has something else.");
                                return None;
                            }
                        };
                        match ac.peer_addr() {
                            Err(e) => {
                                debug!("Could not obtain Peer IP: {:?} - dropping this peer.", e);
                                true
                            }
                            Ok(s) => {
                                match ac.peer_kind() {
                                    CrustUser::Node =>
                                        whitelisted_node_ips.as_ref()
                                              .map_or(false, |ips| !ips.contains(&s.ip())),
                                    CrustUser::Client =>
                                        whitelisted_client_ips.as_ref()
                                              .map_or(false, |ips| !ips.contains(&s.ip())),
                                }
                            }
                        }
                    };
                    if should_drop { Some(peer) } else { None }
                })
                })
                .collect();

        for peer in peers_to_terminate {
            peer.borrow_mut().terminate(core, poll);
        }
    }
}

impl Drop for ConfigRefresher {
    fn drop(&mut self) {
        let _ = self.tx.send(DebouncedEvent::Error(
            notify::Error::Generic(String::from(MAGIC_SHUTDOWN_MSG)),
            None,
        ));
    }
}
