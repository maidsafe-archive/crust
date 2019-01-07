// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod cache;
mod try_peer;

pub use self::cache::Cache;
use self::try_peer::TryPeer;
use crate::common::{BootstrapDenyReason, CoreTimer, CrustUser, NameHash, PeerInfo, State, Uid};
use crate::main::bootstrap::Cache as BootstrapCache;
use crate::main::{ActiveConnection, ConnectionMap, CrustConfig, CrustError, Event, EventLoopCore};
use crate::service_discovery::ServiceDiscovery;
use mio::{Poll, Token};
use mio_extras::timer::Timeout;
use rand;
use rand::seq::SliceRandom;
use safe_crypto::{PublicEncryptKey, SecretEncryptKey};
use socket_collection::TcpSock;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::mem;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

const BOOTSTRAP_TIMEOUT_SEC: u64 = 10;
const SERVICE_DISCOVERY_TIMEOUT_SEC: u64 = 1;
const BOOTSTRAP_TIMER_ID: u8 = 0;
const SERVICE_DISCOVERY_TIMER_ID: u8 = BOOTSTRAP_TIMER_ID + 1;
const MAX_CONTACTS_EXPECTED: usize = 1500;

/// Connection bootstrap state that
///
/// 1. attempts service discovery,
/// 2. if no peers are found, tries cached ones,
/// 3. if no success again, tries peers hard coded in the config.
pub struct Bootstrap<UID: Uid> {
    token: Token,
    cm: ConnectionMap<UID>,
    peers: Vec<PeerInfo>,
    name_hash: NameHash,
    our_addrs: HashSet<SocketAddr>,
    our_uid: UID,
    our_role: CrustUser,
    event_tx: crate::CrustEventSender<UID>,
    sd_meta: Option<ServiceDiscMeta>,
    bs_timer: CoreTimer,
    bs_timeout: Timeout,
    children: HashSet<Token>,
    self_weak: Weak<RefCell<Bootstrap<UID>>>,
    our_pk: PublicEncryptKey,
    our_sk: SecretEncryptKey,
}

impl<UID: Uid> Bootstrap<UID> {
    /// # Args
    ///
    /// `our_addrs` - addresses sent to remote peer to check external reachablity with us.
    /// `our_role` - Crust role: client or node. Clients are never checked for external
    ///     reachability.
    pub fn start(
        core: &mut EventLoopCore,
        poll: &Poll,
        name_hash: NameHash,
        our_addrs: HashSet<SocketAddr>,
        our_uid: UID,
        our_role: CrustUser,
        cm: ConnectionMap<UID>,
        config: CrustConfig,
        blacklist: HashSet<SocketAddr>,
        token: Token,
        service_discovery_token: Token,
        event_tx: crate::CrustEventSender<UID>,
        our_pk: PublicEncryptKey,
        our_sk: &SecretEncryptKey,
    ) -> crate::Res<()> {
        let bs_timer = CoreTimer::new(token, BOOTSTRAP_TIMER_ID);
        let bs_timeout = core.set_timeout(Duration::from_secs(BOOTSTRAP_TIMEOUT_SEC), bs_timer);
        let sd_meta = match seek_peers(core, service_discovery_token, token) {
            Ok((rx, timeout)) => Some(ServiceDiscMeta { rx, timeout }),
            Err(CrustError::ServiceDiscNotEnabled) => None,
            Err(e) => {
                warn!("Failed to seek peers using service discovery: {:?}", e);
                return Err(e);
            }
        };

        let peers = shuffled_bootstrap_peers(core.user_data().peers(), config.clone(), blacklist);
        let state = Rc::new(RefCell::new(Self {
            token,
            cm,
            peers,
            name_hash,
            our_addrs,
            our_uid,
            our_role,
            event_tx,
            sd_meta,
            bs_timer,
            bs_timeout,
            children: HashSet::with_capacity(MAX_CONTACTS_EXPECTED),
            self_weak: Weak::new(),
            our_pk,
            our_sk: our_sk.clone(),
        }));

        state.borrow_mut().self_weak = Rc::downgrade(&state);

        let _ = core.insert_state(token, state.clone());

        if state.borrow().sd_meta.is_none() {
            state.borrow_mut().begin_bootstrap(core, poll);
        }

        Ok(())
    }

    fn begin_bootstrap(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        let peers = mem::replace(&mut self.peers, Vec::new());
        if peers.is_empty() {
            let _ = self.event_tx.send(Event::BootstrapFailed);
            return self.terminate(core, poll);
        }

        for peer in peers {
            let self_weak = self.self_weak.clone();
            let finish = move |core: &mut EventLoopCore, poll: &Poll, child, res| {
                if let Some(self_rc) = self_weak.upgrade() {
                    self_rc.borrow_mut().handle_result(core, poll, child, res)
                }
            };

            if let Ok(child) = TryPeer::start(
                core,
                poll,
                peer,
                self.our_uid,
                self.name_hash,
                self.our_addrs.clone(),
                self.our_role,
                self.our_pk,
                &self.our_sk,
                Box::new(finish),
            ) {
                let _ = self.children.insert(child);
            }
        }
        self.maybe_terminate(core, poll);
    }

    fn handle_result(
        &mut self,
        core: &mut EventLoopCore,
        poll: &Poll,
        child: Token,
        res: Result<(TcpSock, PeerInfo, UID), (PeerInfo, Option<BootstrapDenyReason>)>,
    ) {
        let _ = self.children.remove(&child);
        match res {
            Ok((socket, peer_info, peer_id)) => {
                self.terminate(core, poll);
                return ActiveConnection::start(
                    core,
                    poll,
                    child,
                    socket,
                    self.cm.clone(),
                    self.our_uid,
                    peer_id,
                    // Note; We bootstrap only to Nodes
                    CrustUser::Node,
                    Event::BootstrapConnect(peer_id, peer_info.addr),
                    self.event_tx.clone(),
                );
            }
            Err((bad_peer, opt_reason)) => {
                {
                    let bootstrap_cache = core.user_data_mut();
                    bootstrap_cache.remove(&bad_peer);
                    if let Err(e) = bootstrap_cache.commit() {
                        info!("Failed to write bootstrap cache to disk: {}", e);
                    }
                }

                if let Some(reason) = opt_reason {
                    let (err_msg, is_err_fatal) = match reason {
                        BootstrapDenyReason::InvalidNameHash => ("Network name mismatch.", false),
                        BootstrapDenyReason::FailedExternalReachability => (
                            "Bootstrappee node could not establish connection to us.",
                            true,
                        ),
                        BootstrapDenyReason::NodeNotWhitelisted => {
                            ("Our Node is not whitelisted", false)
                        }
                        BootstrapDenyReason::ClientNotWhitelisted => {
                            ("Our Client is not whitelisted", false)
                        }
                    };
                    if is_err_fatal {
                        error!("Failed to Bootstrap: ({:?}) {}", reason, err_msg);
                        self.terminate(core, poll);
                        let _ = self.event_tx.send(Event::BootstrapFailed);
                        return;
                    } else {
                        info!(
                            "Failed to Bootstrap with {:?}: ({:?}) {}",
                            bad_peer, reason, err_msg
                        );
                    }
                }
            }
        }
        self.maybe_terminate(core, poll);
    }

    fn maybe_terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        if self.children.is_empty() {
            error!("Bootstrapper has no active children left - bootstrap has failed");
            self.terminate(core, poll);
            let _ = self.event_tx.send(Event::BootstrapFailed);
        }
    }

    fn terminate_children(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        for child in self.children.drain() {
            let child = match core.get_state(child) {
                Some(state) => state,
                None => continue,
            };

            child.borrow_mut().terminate(core, poll);
        }
    }
}

impl<UID: Uid> State<BootstrapCache> for Bootstrap<UID> {
    fn timeout(&mut self, core: &mut EventLoopCore, poll: &Poll, timer_id: u8) {
        if timer_id == self.bs_timer.timer_id {
            let _ = self.event_tx.send(Event::BootstrapFailed);
            return self.terminate(core, poll);
        }

        let rx = unwrap!(self.sd_meta.take()).rx;

        while let Ok(listeners) = rx.try_recv() {
            self.peers.extend(listeners);
        }

        self.begin_bootstrap(core, poll);
    }

    fn terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        self.terminate_children(core, poll);
        if let Some(sd_meta) = self.sd_meta.take() {
            let _ = core.cancel_timeout(&sd_meta.timeout);
        }
        let _ = core.remove_state(self.token);
        let _ = core.cancel_timeout(&self.bs_timeout);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

/// Puts given peer contacts into bootstrap cache which is then written to disk.
pub fn cache_peer_info(core: &mut EventLoopCore, peer_info: PeerInfo, config: &CrustConfig) {
    let hard_coded_peers = &unwrap!(config.lock()).cfg.hard_coded_contacts;
    if hard_coded_peers.contains(&peer_info) {
        debug!("Connecting to hard coded peer - it won't be cached.");
        return;
    }

    let bootstrap_cache = core.user_data_mut();
    bootstrap_cache.put(peer_info);
    if let Err(e) = bootstrap_cache.commit() {
        info!("Failed to write bootstrap cache to disk: {}", e);
    }
}

struct ServiceDiscMeta {
    rx: Receiver<Vec<PeerInfo>>,
    timeout: Timeout,
}

/// Runs service discovery state with a timeout. When timeout happens, `Bootstrap::timeout()`
/// callback is called.
fn seek_peers(
    core: &mut EventLoopCore,
    service_discovery_token: Token,
    token: Token,
) -> crate::Res<(Receiver<Vec<PeerInfo>>, Timeout)> {
    if let Some(state) = core.get_state(service_discovery_token) {
        let mut state = state.borrow_mut();
        let state = unwrap!(state
            .as_any()
            .downcast_mut::<ServiceDiscovery<BootstrapCache>>());

        let (obs, rx) = mpsc::channel();
        state.register_observer(obs);
        state.seek_peers()?;
        let timeout = core.set_timeout(
            Duration::from_secs(SERVICE_DISCOVERY_TIMEOUT_SEC),
            CoreTimer::new(token, SERVICE_DISCOVERY_TIMER_ID),
        );

        Ok((rx, timeout))
    } else {
        Err(CrustError::ServiceDiscNotEnabled)
    }
}

/// Peers from bootstrap cache and hard coded contacts are shuffled individually.
fn shuffled_bootstrap_peers(
    cached_peers: HashSet<PeerInfo>,
    config: CrustConfig,
    blacklist: HashSet<SocketAddr>,
) -> Vec<PeerInfo> {
    let mut peers = Vec::with_capacity(MAX_CONTACTS_EXPECTED);
    let mut rng = rand::thread_rng();

    let mut cached: Vec<_> = cached_peers.iter().cloned().collect();
    cached.shuffle(&mut rng);
    peers.extend(cached);

    let mut hard_coded = unwrap!(config.lock()).cfg.hard_coded_contacts.clone();
    hard_coded.shuffle(&mut rng);
    peers.extend(hard_coded);

    peers.retain(|peer| !blacklist.contains(&peer.addr));
    peers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ipv4_addr;
    use crate::main::ConfigWrapper;
    use crate::tests::utils::{peer_info_with_rand_key, test_bootstrap_cache, test_core};
    use crate::Config;
    use std::sync::{Arc, Mutex};

    mod cache_peer_info {
        use super::*;

        #[test]
        fn it_puts_peer_contacts_into_bootstrap_cache() {
            let mut core = test_core(test_bootstrap_cache());
            let peer_info = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
            let config = Config::default();
            let config = Arc::new(Mutex::new(ConfigWrapper::new(config)));

            cache_peer_info(&mut core, peer_info, &config);

            let cached_peers = core.user_data().peers();
            assert_eq!(cached_peers.len(), 1);
            assert_eq!(unwrap!(cached_peers.iter().next()), &peer_info);
        }

        #[test]
        fn it_wont_cache_hard_coded_peer() {
            let mut core = test_core(test_bootstrap_cache());
            let peer_info = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
            let mut config = Config::default();
            config.hard_coded_contacts = vec![peer_info];
            let config = Arc::new(Mutex::new(ConfigWrapper::new(config)));

            cache_peer_info(&mut core, peer_info, &config);

            let cached_peers = core.user_data().peers();
            assert!(cached_peers.is_empty());
        }
    }

    mod seek_pers {
        use super::*;

        #[test]
        fn it_returns_error_when_service_discovery_token_is_not_registered() {
            let dummy_token = Token(99999);
            let bootstrap_cache = test_bootstrap_cache();
            let mut core = test_core(bootstrap_cache);

            let res = seek_peers(&mut core, dummy_token, dummy_token);

            match res {
                Err(CrustError::ServiceDiscNotEnabled) => (),
                res => panic!("Unexpected result: {:?}", res),
            }
        }
    }

    mod shuffled_bootstrap_peers {
        use super::*;

        #[test]
        fn it_returns_cached_and_hard_coded_peers() {
            let peer1 = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
            let peer2 = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 5, 5000));
            let mut config = Config::default();
            config.hard_coded_contacts = vec![peer1];
            let config = Arc::new(Mutex::new(ConfigWrapper::new(config)));
            let mut cached_peers = HashSet::new();
            let _ = cached_peers.insert(peer2);

            let peers = shuffled_bootstrap_peers(cached_peers, config, Default::default());

            assert_eq!(peers.len(), 2);
            assert!(peers.contains(&peer1));
            assert!(peers.contains(&peer2));
        }

        #[test]
        fn it_filters_out_blacklisted_addresses() {
            let peer1 = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
            let peer2 = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 5, 5000));
            let mut config = Config::default();
            config.hard_coded_contacts = vec![peer1];
            let config = Arc::new(Mutex::new(ConfigWrapper::new(config)));
            let mut cached_peers = HashSet::new();
            let _ = cached_peers.insert(peer2);
            let mut blacklisted = HashSet::new();
            let _ = blacklisted.insert(ipv4_addr(1, 2, 3, 4, 4000));

            let peers = shuffled_bootstrap_peers(cached_peers, config, blacklisted);

            assert_eq!(peers.len(), 1);
            assert!(peers.contains(&peer2));
        }
    }

    mod bootstrap {
        use super::*;

        mod handle_result {
            use super::*;
            use crate::tests::utils::{get_event_sender, rand_uid, UniqueId};
            use safe_crypto::gen_encrypt_keypair;
            use std::collections::HashMap;

            mod when_result_is_error {
                use super::*;

                #[test]
                fn it_removes_peer_info_from_bootstrap_cache() {
                    let bootstrap_cache = test_bootstrap_cache();
                    let peer_info = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
                    bootstrap_cache.put(peer_info);
                    let mut core = test_core(bootstrap_cache);
                    let poll = unwrap!(Poll::new());

                    let config = Config::default();
                    let config = Arc::new(Mutex::new(ConfigWrapper::new(config)));
                    let dummy_service_discovery_token = Token(9999);

                    let (our_pk, our_sk) = gen_encrypt_keypair();
                    let (event_tx, _event_rx) = get_event_sender();
                    let token = Token(1);
                    let conn_map = Arc::new(Mutex::new(HashMap::new()));

                    unwrap!(Bootstrap::start(
                        &mut core,
                        &poll,
                        [1; 32],
                        Default::default(),
                        rand_uid(),
                        CrustUser::Client,
                        conn_map,
                        config,
                        HashSet::new(),
                        token,
                        dummy_service_discovery_token,
                        event_tx,
                        our_pk,
                        &our_sk
                    ));

                    let state = unwrap!(core.get_state(token));
                    let mut state = state.borrow_mut();
                    let bootstrap_state =
                        unwrap!(state.as_any().downcast_mut::<Bootstrap<UniqueId>>());
                    bootstrap_state.handle_result(
                        &mut core,
                        &poll,
                        Token(2),
                        Err((peer_info, None)),
                    );

                    let cached_peers = core.user_data().peers();
                    assert!(cached_peers.is_empty());
                }

                #[test]
                fn when_reason_is_invalid_hash_bootstrap_is_not_terminated() {
                    let bootstrap_cache = test_bootstrap_cache();
                    let peer_info = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
                    // there must be at least one bootstrap peer, otherwise Bootstrap state
                    // will be terminated too soon.
                    bootstrap_cache.put(peer_info);
                    let mut core = test_core(bootstrap_cache);
                    let poll = unwrap!(Poll::new());

                    let config = Config::default();
                    let config = Arc::new(Mutex::new(ConfigWrapper::new(config)));
                    let dummy_service_discovery_token = Token(9999);

                    let (our_pk, our_sk) = gen_encrypt_keypair();
                    let (event_tx, _event_rx) = get_event_sender();
                    let token = Token(1);
                    let conn_map = Arc::new(Mutex::new(HashMap::new()));

                    unwrap!(Bootstrap::start(
                        &mut core,
                        &poll,
                        [1; 32],
                        Default::default(),
                        rand_uid(),
                        CrustUser::Client,
                        conn_map,
                        config,
                        HashSet::new(),
                        token,
                        dummy_service_discovery_token,
                        event_tx,
                        our_pk,
                        &our_sk
                    ));

                    let state = unwrap!(core.get_state(token));
                    let mut state = state.borrow_mut();
                    let bootstrap_state =
                        unwrap!(state.as_any().downcast_mut::<Bootstrap<UniqueId>>());
                    bootstrap_state.handle_result(
                        &mut core,
                        &poll,
                        Token(2),
                        Err((peer_info, Some(BootstrapDenyReason::InvalidNameHash))),
                    );

                    let state = core.get_state(token);
                    assert!(state.is_some());
                }
            }
        }
    }
}
