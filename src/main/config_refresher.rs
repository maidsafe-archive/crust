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

use common::{Core, CoreTimer, CrustUser, State, Uid};
use main::{ActiveConnection, ConfigFile, ConnectionMap};
use mio::{Poll, Token};
use mio::timer::Timeout;
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

const REFRESH_INTERVAL_SEC: u64 = 30;

pub struct ConfigRefresher<UID: Uid> {
    token: Token,
    timer: CoreTimer,
    timeout: Timeout,
    cm: ConnectionMap<UID>,
    config: ConfigFile,
}

impl<UID: Uid> ConfigRefresher<UID> {
    pub fn start(
        core: &mut Core,
        token: Token,
        cm: ConnectionMap<UID>,
        config: ConfigFile,
    ) -> ::Res<()> {
        trace!("Entered state ConfigRefresher");

        let timer = CoreTimer::new(token, 0);
        let timeout = core.set_timeout(
            Duration::from_secs(REFRESH_INTERVAL_SEC),
            timer,
        )?;

        let state = Rc::new(RefCell::new(ConfigRefresher {
            token: token,
            timer: timer,
            timeout: timeout,
            cm: cm,
            config: config,
        }));
        let _ = core.insert_state(token, state);

        Ok(())
    }
}

impl<UID: Uid> State for ConfigRefresher<UID> {
    fn terminate(&mut self, core: &mut Core, _poll: &Poll) {
        let _ = core.cancel_timeout(&self.timeout);
        let _ = core.remove_state(self.token);
    }

    fn timeout(&mut self, core: &mut Core, poll: &Poll, _timer_id: u8) {
        self.timeout =
            match core.set_timeout(Duration::from_secs(REFRESH_INTERVAL_SEC), self.timer) {
                Ok(t) => t,
                Err(e) => {
                    debug!("Config Refresher Timer Errored out: {:?}", e);
                    return self.terminate(core, poll);
                }
            };

        match self.config.reload_and_check_modified() {
            Ok(_) => (),
            Err(e) => {
                debug!(
                    "Could not read Crust config (it's rescheduled to be read): {:?}",
                    e
                );
            }
        };

        let config = self.config.read();
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
            unwrap!(self.cm.lock())
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

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
