// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use common::{Core, CoreTimer, CrustUser, State, Uid};
use main::{read_config_file, ActiveConnection, ConnectionMap, CrustConfig};
use mio::{Poll, Token};
use mio_extras::timer::Timeout;
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
    config: CrustConfig,
}

impl<UID: Uid> ConfigRefresher<UID> {
    pub fn start(
        core: &mut Core,
        token: Token,
        cm: ConnectionMap<UID>,
        config: CrustConfig,
    ) -> ::Res<()> {
        trace!("Entered state ConfigRefresher");

        let timer = CoreTimer::new(token, 0);
        let timeout = core.set_timeout(Duration::from_secs(REFRESH_INTERVAL_SEC), timer);

        let state = Rc::new(RefCell::new(ConfigRefresher {
            token,
            timer,
            timeout,
            cm,
            config,
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
        self.timeout = core.set_timeout(Duration::from_secs(REFRESH_INTERVAL_SEC), self.timer);

        let config = match read_config_file() {
            Ok(cfg) => cfg,
            Err(e) => {
                debug!(
                    "Could not read Crust config (it's rescheduled to be read): {:?}",
                    e
                );
                return;
            }
        };

        let whitelisted_node_ips = config.whitelisted_node_ips.clone();
        let whitelisted_client_ips = config.whitelisted_client_ips.clone();

        if !unwrap!(self.config.lock()).check_for_refresh_and_reset_modified(config)
            || (whitelisted_node_ips.is_none() && whitelisted_client_ips.is_none())
        {
            return;
        }

        trace!(
            "Crust config has been updated - going to purge any nodes or clients that are no \
             longer whitelisted"
        );

        // Peers collected to avoid keeping the mutex lock alive which might lead to deadlock
        let peers_to_terminate: Vec<_> = unwrap!(self.cm.lock())
            .values()
            .filter_map(|cid| {
                cid.active_connection
                    .and_then(|token| core.get_state(token))
                    .and_then(|peer| {
                        let should_drop = {
                            let mut state = peer.borrow_mut();
                            let ac = match state.as_any().downcast_mut::<ActiveConnection<UID>>() {
                                Some(ac) => ac,
                                None => {
                                    warn!(
                                        "Token reserved for ActiveConnection has something else."
                                    );
                                    return None;
                                }
                            };
                            match ac.peer_addr() {
                                Err(e) => {
                                    debug!(
                                        "Could not obtain Peer IP: {:?} - dropping this peer.",
                                        e
                                    );
                                    true
                                }
                                Ok(s) => match ac.peer_kind() {
                                    CrustUser::Node => whitelisted_node_ips
                                        .as_ref()
                                        .map_or(false, |ips| !ips.contains(&s.ip())),
                                    CrustUser::Client => whitelisted_client_ips
                                        .as_ref()
                                        .map_or(false, |ips| !ips.contains(&s.ip())),
                                },
                            }
                        };
                        if should_drop {
                            Some(peer)
                        } else {
                            None
                        }
                    })
            }).collect();

        for peer in peers_to_terminate {
            peer.borrow_mut().terminate(core, poll);
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
