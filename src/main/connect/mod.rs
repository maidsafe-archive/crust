// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod exchange_msg;

use self::exchange_msg::ExchangeMsg;
use crate::common::{CoreTimer, CrustUser, ExternalReachability, NameHash, PeerInfo, State, Uid};
use crate::main::bootstrap;
use crate::main::{
    ActiveConnection, ConnectionCandidate, ConnectionMap, CrustConfig, CrustError, Event,
    EventLoopCore, PrivConnectionInfo, PubConnectionInfo,
};
use mio::{Poll, Token};
use mio_extras::timer::Timeout;
use safe_crypto::{PublicEncryptKey, SecretEncryptKey, SharedSecretKey};
use socket_collection::{DecryptContext, EncryptContext, TcpSock};
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::{Rc, Weak};
use std::time::Duration;

const TIMEOUT_SEC: u64 = 60;

/// Atempts multiple connections to remote peer, but yields the first successful one.
pub struct Connect<UID: Uid> {
    token: Token,
    timeout: Timeout,
    cm: ConnectionMap<UID>,
    our_nh: NameHash,
    our_id: UID,
    their_id: UID,
    self_weak: Weak<RefCell<Connect<UID>>>,
    children: HashSet<Token>,
    event_tx: crate::CrustEventSender<UID>,
    our_pk: PublicEncryptKey,
    config: CrustConfig,
    ext_reachability: ExternalReachability,
}

impl<UID: Uid> Connect<UID> {
    pub fn start(
        core: &mut EventLoopCore,
        poll: &Poll,
        our_ci: PrivConnectionInfo<UID>,
        their_ci: PubConnectionInfo<UID>,
        cm: ConnectionMap<UID>,
        our_nh: NameHash,
        event_tx: crate::CrustEventSender<UID>,
        our_pk: PublicEncryptKey,
        our_sk: &SecretEncryptKey,
        config: CrustConfig,
        ext_reachability: ExternalReachability,
    ) -> crate::Res<()> {
        let their_id = their_ci.id;
        let their_direct = their_ci.for_direct;

        if their_direct.is_empty() {
            let _ = event_tx.send(Event::ConnectFailure(their_id));
            return Err(CrustError::InsufficientConnectionInfo);
        }

        let token = core.get_new_token();

        let state = Rc::new(RefCell::new(Self {
            token,
            timeout: core.set_timeout(Duration::from_secs(TIMEOUT_SEC), CoreTimer::new(token, 0)),
            cm,
            our_nh,
            our_id: our_ci.id,
            their_id,
            self_weak: Weak::new(),
            children: HashSet::with_capacity(their_direct.len()),
            event_tx,
            our_pk,
            config,
            ext_reachability,
        }));

        state.borrow_mut().self_weak = Rc::downgrade(&state);

        let their_pk = their_ci.our_pk;
        let sockets = their_direct
            .into_iter()
            .filter_map(|addr| {
                let info = PeerInfo::new(addr, their_pk);
                TcpSock::connect(&addr).map(|sock| (sock, info)).ok()
            })
            .collect::<Vec<_>>();

        for (mut socket, peer_info) in sockets {
            let shared_key = our_sk.shared_secret(&their_ci.our_pk);
            match (
                socket.set_encrypt_ctx(EncryptContext::anonymous_encrypt(their_ci.our_pk)),
                socket.set_decrypt_ctx(DecryptContext::authenticated(shared_key.clone())),
            ) {
                (Ok(_), Ok(_)) => state
                    .borrow_mut()
                    .exchange_msg(core, poll, socket, peer_info, shared_key),
                res => warn!("Failed to set encrypt/decrypt context: {:?}", res),
            }
        }

        let _ = core.insert_state(token, state);

        Ok(())
    }

    fn exchange_msg(
        &mut self,
        core: &mut EventLoopCore,
        poll: &Poll,
        socket: TcpSock,
        peer_info: PeerInfo,
        shared_key: SharedSecretKey,
    ) {
        let self_weak = self.self_weak.clone();
        let handler = move |core: &mut EventLoopCore, poll: &Poll, child, res| {
            if let Some(self_rc) = self_weak.upgrade() {
                self_rc
                    .borrow_mut()
                    .handle_exchange_msg(core, poll, child, res, peer_info);
            }
        };

        if let Ok(child) = ExchangeMsg::start(
            core,
            poll,
            socket,
            self.our_id,
            self.their_id,
            self.our_nh,
            self.cm.clone(),
            self.our_pk,
            shared_key,
            self.ext_reachability.clone(),
            Box::new(handler),
        ) {
            let _ = self.children.insert(child);
        }
        self.maybe_terminate(core, poll);
    }

    fn handle_exchange_msg(
        &mut self,
        core: &mut EventLoopCore,
        poll: &Poll,
        child: Token,
        res: Option<TcpSock>,
        peer_info: PeerInfo,
    ) {
        let _ = self.children.remove(&child);
        if let Some(socket) = res {
            bootstrap::cache_peer_info(core, peer_info, &self.config);
            let self_weak = self.self_weak.clone();
            let handler = move |core: &mut EventLoopCore, poll: &Poll, child, res| {
                if let Some(self_rc) = self_weak.upgrade() {
                    self_rc
                        .borrow_mut()
                        .handle_connection_candidate(core, poll, child, res);
                }
            };

            if let Ok(child) = ConnectionCandidate::start(
                core,
                poll,
                child,
                socket,
                self.cm.clone(),
                self.our_id,
                self.their_id,
                Box::new(handler),
            ) {
                let _ = self.children.insert(child);
            }
        } else {
            self.remove_peer_from_cache(core, &peer_info);
        }
        self.maybe_terminate(core, poll);
    }

    fn handle_connection_candidate(
        &mut self,
        core: &mut EventLoopCore,
        poll: &Poll,
        child: Token,
        res: Option<TcpSock>,
    ) {
        let _ = self.children.remove(&child);
        if let Some(socket) = res {
            self.terminate(core, poll);
            return ActiveConnection::start(
                core,
                poll,
                child,
                socket,
                self.cm.clone(),
                self.our_id,
                self.their_id,
                // Note; We connect only to Nodes
                CrustUser::Node,
                Event::ConnectSuccess(self.their_id),
                self.event_tx.clone(),
            );
        }
        self.maybe_terminate(core, poll);
    }

    fn remove_peer_from_cache(&self, core: &mut EventLoopCore, peer_info: &PeerInfo) {
        let bootstrap_cache = core.user_data_mut();
        bootstrap_cache.remove(peer_info);
        if let Err(e) = bootstrap_cache.commit() {
            info!("Failed to write bootstrap cache to disk: {}", e);
        }
    }

    fn maybe_terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        if self.children.is_empty() {
            self.terminate(core, poll);
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

impl<UID: Uid> State<bootstrap::Cache> for Connect<UID> {
    fn timeout(&mut self, core: &mut EventLoopCore, poll: &Poll, _timer_id: u8) {
        debug!("Connect to peer {:?} timed out", self.their_id);
        self.terminate(core, poll);
    }

    fn terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        self.terminate_children(core, poll);

        let _ = core.cancel_timeout(&self.timeout);
        let _ = core.remove_state(self.token);

        if !unwrap!(self.cm.lock()).contains_key(&self.their_id) {
            let _ = self.event_tx.send(Event::ConnectFailure(self.their_id));
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod connect {
        use super::*;
        use crate::common::ipv4_addr;
        use crate::main::ConfigWrapper;
        use crate::tests::utils::{
            get_event_sender, peer_info_with_rand_key, rand_uid, test_bootstrap_cache, test_core,
            UniqueId,
        };
        use crate::Config;
        use safe_crypto::gen_encrypt_keypair;
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        fn test_priv_conn_info() -> (PrivConnectionInfo<UniqueId>, SecretEncryptKey) {
            let (pk, sk) = gen_encrypt_keypair();
            let conn_info = PrivConnectionInfo {
                id: rand_uid(),
                for_direct: vec![ipv4_addr(1, 2, 3, 4, 4000)],
                our_pk: pk,
            };
            (conn_info, sk)
        }

        #[test]
        fn remove_peer_from_cache_does_what_it_says() {
            let cached_peer = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
            let bootstrap_cache = test_bootstrap_cache();
            bootstrap_cache.put(cached_peer);
            let mut core = test_core(bootstrap_cache);
            let poll = unwrap!(Poll::new());

            let (our_ci, our_sk) = test_priv_conn_info();
            let our_pk = our_ci.our_pk;
            let (their_ci, _) = test_priv_conn_info();
            let their_ci = their_ci.to_pub_connection_info();
            let config = Config::default();
            let config = Arc::new(Mutex::new(ConfigWrapper::new(config)));

            let conn_map = Arc::new(Mutex::new(HashMap::new()));
            let (event_tx, _event_rx) = get_event_sender();
            unwrap!(Connect::start(
                &mut core,
                &poll,
                our_ci,
                their_ci.clone(),
                conn_map,
                [1; 32],
                event_tx,
                our_pk,
                &our_sk,
                config,
                ExternalReachability::NotRequired,
            ));

            let connect_state_token = Token(0);
            let state = unwrap!(core.get_state(connect_state_token));
            let mut state = state.borrow_mut();
            let connect_state = unwrap!(state.as_any().downcast_mut::<Connect<UniqueId>>());

            connect_state.remove_peer_from_cache(&mut core, &cached_peer);

            let cached_peers = core.user_data().peers();
            assert!(cached_peers.is_empty());
        }
    }
}
