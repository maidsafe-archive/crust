// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::{ipv4_addr, PeerInfo, State};
use crate::main::{CrustData, EventLoopCore, EventToken};
use crate::nat::GetExtAddr;
use mio::{Poll, Token};
use safe_crypto::{PublicEncryptKey, SecretEncryptKey};
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};

/// When peer is tested, if it's still online, we send an encrypted request and wait for response.
/// This is the maximum time we wait before declaring that peer is dead.
const PEER_TEST_TIMEOUT_SEC: u64 = 30;

/// Bootstrap cache validator tests inactive cached peers if they are still alive.
/// It receives peers from async in-memory channel.
/// Cache validator is a future/state that never finishes.
pub struct CacheValidator {
    token: Token,
    our_pk: PublicEncryptKey,
    our_sk: SecretEncryptKey,
    /// Tokens for in progress states testing peer connectivity.
    sent_requests: HashSet<Token>,
    /// When need to reference self from the callbacks.
    self_weak: Weak<RefCell<CacheValidator>>,
}

impl CacheValidator {
    /// Starts running bootstrap cache entry validation.
    pub fn start(
        core: &mut EventLoopCore,
        token: Token,
        our_pk: PublicEncryptKey,
        our_sk: SecretEncryptKey,
    ) -> crate::Res<()> {
        let state = Rc::new(RefCell::new(Self {
            token,
            our_pk,
            our_sk,
            sent_requests: Default::default(),
            self_weak: Default::default(),
        }));
        state.borrow_mut().self_weak = Rc::downgrade(&state);
        let _ = core.insert_state(token, state.clone());

        Ok(())
    }

    /// Sends STUN requests to cached peers that recently been inactive.
    pub fn ping_inactive_peers(
        &mut self,
        core: &mut EventLoopCore,
        poll: &Poll,
        inactive_peers: HashSet<PeerInfo>,
    ) {
        debug!("Testing {} inactive cached peers.", inactive_peers.len());
        for peer in inactive_peers {
            self.ping_peer_and_cache_alive(core, poll, peer);
        }
    }

    /// Send STUN request to given peer and wait for response.
    /// If response arrives within timeout, peer is added to the bootstrap cache head.
    fn ping_peer_and_cache_alive(&mut self, core: &mut EventLoopCore, poll: &Poll, peer: PeerInfo) {
        let self_weak = self.self_weak.clone();
        let finish = move |core: &mut EventLoopCore,
                           poll: &Poll,
                           request_token,
                           req_status: Result<SocketAddr, ()>| {
            if let Some(self_rc) = self_weak.upgrade() {
                let mut self_rc = self_rc.borrow_mut();
                let _ = self_rc.sent_requests.remove(&request_token);
                if req_status.is_ok() {
                    let expired_peers = core.user_data_mut().bootstrap_cache.put(peer);
                    if !expired_peers.is_empty() {
                        self_rc.ping_inactive_peers(core, poll, expired_peers);
                    }
                }
            }
        };
        if let Ok(request_token) = GetExtAddr::start(
            core,
            poll,
            ipv4_addr(0, 0, 0, 0, 0),
            &peer,
            self.our_pk,
            &self.our_sk,
            Some(PEER_TEST_TIMEOUT_SEC),
            Box::new(finish),
        ) {
            let _ = self.sent_requests.insert(request_token);
        }
    }

    /// Terminates any in-progress requests.
    fn terminate_requests(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        for req_token in self.sent_requests.drain() {
            let req_state = match core.get_state(req_token) {
                Some(state) => state,
                None => continue,
            };
            req_state.borrow_mut().terminate(core, poll);
        }
    }
}

impl State<CrustData> for CacheValidator {
    fn terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        self.terminate_requests(core, poll);
        let _ = core.remove_state(self.token);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

/// Schedules tests for inactive cached bootstrap peers.
pub fn test_inactive_cached_peers(core: &mut EventLoopCore, poll: &Poll, peers: HashSet<PeerInfo>) {
    if let Some(state) = core.get_state(EventToken::BootstrapCacheValidator.into()) {
        if let Some(validator) = state.borrow_mut().as_any().downcast_mut::<CacheValidator>() {
            validator.ping_inactive_peers(core, poll, peers);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{spawn_event_loop, CoreMessage};
    use crate::main::{bootstrap, Event};
    use crate::tests::utils::test_service;
    use safe_crypto::gen_encrypt_keypair;
    use std::sync::mpsc;
    use std::time::Duration;

    mod ping_inactive_peers {
        use super::*;

        #[test]
        fn it_readds_peers_to_cache_that_are_still_alive() {
            let (mut service, event_rx) = test_service();
            unwrap!(service.start_listening_tcp());
            let peer_port = expect_event!(event_rx, Event::ListenerStarted(port) => port);
            let peer_pk = service.pub_key();
            let remote_peer = PeerInfo::new(ipv4_addr(127, 0, 0, 1, peer_port), peer_pk);

            let init_crust_data = move || {
                let bootstrap_cache = bootstrap::Cache::new(Default::default());
                CrustData::new(bootstrap_cache)
            };
            let el = unwrap!(spawn_event_loop(0, None, init_crust_data));

            let (our_pk, our_sk) = gen_encrypt_keypair();
            let expired_peers: HashSet<_> = vec![remote_peer].drain(..).collect();
            unwrap!(el.send(CoreMessage::new(move |core, poll| {
                unwrap!(CacheValidator::start(
                    core,
                    EventToken::BootstrapCacheValidator.into(),
                    our_pk,
                    our_sk
                ));
                test_inactive_cached_peers(core, poll, expired_peers);
            })));

            std::thread::sleep(Duration::from_secs(PEER_TEST_TIMEOUT_SEC + 3));
            let (tx, rx) = mpsc::channel();
            unwrap!(
                el.send(CoreMessage::new(move |core: &mut EventLoopCore, _poll| {
                    unwrap!(tx.send(core.user_data().bootstrap_cache.snapshot()));
                }))
            );

            let cached_peers = unwrap!(rx.recv());
            assert_eq!(cached_peers.len(), 1);
        }
    }
}
