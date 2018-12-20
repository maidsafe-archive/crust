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
use crate::common::{
    BootstrapDenyReason, CoreTimer, CrustUser, ExternalReachability, NameHash, PeerInfo, State, Uid,
};
use crate::main::bootstrap::Cache as BootstrapCache;
use crate::main::{ActiveConnection, ConnectionMap, CrustConfig, CrustError, Event, EventLoopCore};
use crate::service_discovery::ServiceDiscovery;
use mio::{Poll, Token};
use mio_extras::timer::Timeout;
use rand::{self, Rng};
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

pub struct Bootstrap<UID: Uid> {
    token: Token,
    cm: ConnectionMap<UID>,
    peers: Vec<PeerInfo>,
    blacklist: HashSet<SocketAddr>,
    name_hash: NameHash,
    ext_reachability: ExternalReachability,
    our_uid: UID,
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
    pub fn start(
        core: &mut EventLoopCore,
        poll: &Poll,
        name_hash: NameHash,
        ext_reachability: ExternalReachability,
        our_uid: UID,
        cm: ConnectionMap<UID>,
        config: CrustConfig,
        blacklist: HashSet<SocketAddr>,
        token: Token,
        service_discovery_token: Token,
        event_tx: crate::CrustEventSender<UID>,
        our_pk: PublicEncryptKey,
        our_sk: &SecretEncryptKey,
    ) -> crate::Res<()> {
        let mut peers = Vec::with_capacity(MAX_CONTACTS_EXPECTED);
        peers.extend(core.user_data().peers());
        peers.extend(unwrap!(config.lock()).cfg.hard_coded_contacts.clone());

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

        let state = Rc::new(RefCell::new(Self {
            token,
            cm,
            peers,
            blacklist,
            name_hash,
            ext_reachability,
            our_uid,
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
        let mut peers = mem::replace(&mut self.peers, Vec::new());
        peers.retain(|peer| !self.blacklist.contains(&peer.addr));
        if peers.is_empty() {
            let _ = self.event_tx.send(Event::BootstrapFailed);
            return self.terminate(core, poll);
        }
        rand::thread_rng().shuffle(&mut peers);

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
                self.ext_reachability.clone(),
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
                {
                    let bootstrap_cache = core.user_data_mut();
                    bootstrap_cache.put(peer_info);
                    if let Err(e) = bootstrap_cache.commit() {
                        info!("Failed to write bootstrap cache to disk: {}", e);
                    }
                }

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
                    let mut is_err_fatal = true;
                    let err_msg = match reason {
                        BootstrapDenyReason::InvalidNameHash => "Network name mismatch.",
                        BootstrapDenyReason::FailedExternalReachability => {
                            "Bootstrappee node could not establish connection to us."
                        }
                        BootstrapDenyReason::NodeNotWhitelisted => {
                            is_err_fatal = false;
                            "Our Node is not whitelisted"
                        }
                        BootstrapDenyReason::ClientNotWhitelisted => {
                            is_err_fatal = false;
                            "Our Client is not whitelisted"
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

struct ServiceDiscMeta {
    rx: Receiver<Vec<PeerInfo>>,
    timeout: Timeout,
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::utils::{peer_info_with_rand_key, test_bootstrap_cache, test_core};

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

    mod bootstrap {
        use super::*;

        mod handle_result {
            use super::*;
            use crate::common::ipv4_addr;
            use crate::main::ConfigWrapper;
            use crate::tests::utils::{get_event_sender, rand_uid, UniqueId};
            use crate::Config;
            use safe_crypto::gen_encrypt_keypair;
            use std::collections::HashMap;
            use std::sync::{Arc, Mutex};

            #[test]
            fn when_result_is_success_it_puts_peer_info_into_bootstrap_cache() {
                let bootstrap_cache = test_bootstrap_cache();
                let mut core = test_core(bootstrap_cache);
                let poll = unwrap!(Poll::new());

                let peer1 = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
                let mut config = Config::default();
                config.hard_coded_contacts = vec![peer1];
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
                    ExternalReachability::NotRequired,
                    rand_uid(),
                    conn_map,
                    config,
                    HashSet::new(),
                    token,
                    dummy_service_discovery_token,
                    event_tx,
                    our_pk,
                    &our_sk
                ));
                let peer_info = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
                let peer_uid = [2; 20];
                let peer_socket = Default::default();

                let state = unwrap!(core.get_state(token));
                let mut state = state.borrow_mut();
                let bootstrap_state = unwrap!(state.as_any().downcast_mut::<Bootstrap<UniqueId>>());
                bootstrap_state.handle_result(
                    &mut core,
                    &poll,
                    Token(2),
                    Ok((peer_socket, peer_info, peer_uid)),
                );

                let cached_peers = core.user_data().peers();
                assert_eq!(unwrap!(cached_peers.iter().next()), &peer_info);
            }

            #[test]
            fn when_result_is_error_it_removes_peer_info_from_bootstrap_cache() {
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
                    ExternalReachability::NotRequired,
                    rand_uid(),
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
                let bootstrap_state = unwrap!(state.as_any().downcast_mut::<Bootstrap<UniqueId>>());
                bootstrap_state.handle_result(&mut core, &poll, Token(2), Err((peer_info, None)));

                let cached_peers = core.user_data().peers();
                assert!(cached_peers.is_empty());
            }
        }
    }
}
