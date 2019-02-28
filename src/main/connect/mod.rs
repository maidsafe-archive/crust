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
use crate::common::{CoreTimer, CrustUser, NameHash, PeerInfo, State};
use crate::main::bootstrap;
use crate::main::{
    ActiveConnection, ConnectionCandidate, CrustData, CrustError, Event, EventLoopCore,
    PrivConnectionInfo, PubConnectionInfo,
};
use crate::PeerId;
use mio::{Poll, Token};
use mio_extras::timer::Timeout;
use safe_crypto::{SecretEncryptKey, SharedSecretKey};
use socket_collection::{DecryptContext, EncryptContext, TcpSock};
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::time::Duration;

const TIMEOUT_SEC: u64 = 60;

/// Atempts multiple connections to remote peer, but yields the first successful one.
pub struct Connect {
    token: Token,
    timeout: Timeout,
    our_nh: NameHash,
    our_id: PeerId,
    their_id: PeerId,
    self_weak: Weak<RefCell<Connect>>,
    children: HashSet<Token>,
    event_tx: crate::CrustEventSender,
    our_global_direct_listeners: HashSet<SocketAddr>,
}

impl Connect {
    pub fn start(
        core: &mut EventLoopCore,
        poll: &Poll,
        our_ci: PrivConnectionInfo,
        their_ci: PubConnectionInfo,
        our_nh: NameHash,
        event_tx: crate::CrustEventSender,
        our_sk: &SecretEncryptKey,
        our_global_direct_listeners: HashSet<SocketAddr>,
    ) -> crate::Res<()> {
        let their_id = their_ci.id;
        let their_direct = their_ci.for_direct;

        if their_direct.is_empty() {
            let _ = event_tx.send(Event::ConnectFailure(their_id));
            return Err(CrustError::InsufficientConnectionInfo);
        }

        let token = core.get_new_token();

        let our_id = our_ci.id;
        let state = Rc::new(RefCell::new(Self {
            token,
            timeout: core.set_timeout(Duration::from_secs(TIMEOUT_SEC), CoreTimer::new(token, 0)),
            our_nh,
            our_id,
            their_id,
            self_weak: Weak::new(),
            children: HashSet::with_capacity(their_direct.len()),
            event_tx,
            our_global_direct_listeners,
        }));

        state.borrow_mut().self_weak = Rc::downgrade(&state);

        let their_pk = their_ci.id.pub_enc_key;
        let sockets = their_direct
            .into_iter()
            .filter_map(|addr| {
                let info = PeerInfo::new(addr, their_pk);
                TcpSock::connect(&addr).map(|sock| (sock, info)).ok()
            })
            .collect::<Vec<_>>();

        for (mut socket, peer_info) in sockets {
            let shared_key = our_sk.shared_secret(&their_pk);
            match (
                socket.set_encrypt_ctx(EncryptContext::anonymous_encrypt(their_pk)),
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
            shared_key,
            self.our_global_direct_listeners.clone(),
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
            bootstrap::cache_peer_info(core, peer_info);
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
        let bootstrap_cache = &mut core.user_data_mut().bootstrap_cache;
        bootstrap_cache.remove(peer_info);
        bootstrap_cache.try_commit();
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

impl State<CrustData> for Connect {
    fn timeout(&mut self, core: &mut EventLoopCore, poll: &Poll, _timer_id: u8) {
        debug!("Connect to peer {:?} timed out", self.their_id);
        self.terminate(core, poll);
    }

    fn terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        self.terminate_children(core, poll);

        let _ = core.cancel_timeout(&self.timeout);
        let _ = core.remove_state(self.token);

        if !core.user_data().connections.contains_key(&self.their_id) {
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
        use crate::tests::utils::{
            get_event_sender, peer_info_with_rand_key, rand_peer_id_and_enc_sk,
            test_bootstrap_cache, test_core,
        };

        fn test_priv_conn_info() -> (PrivConnectionInfo, SecretEncryptKey) {
            let (id, sk) = rand_peer_id_and_enc_sk();
            let conn_info = PrivConnectionInfo {
                id,
                for_direct: vec![ipv4_addr(1, 2, 3, 4, 4000)],
            };
            (conn_info, sk)
        }

        #[test]
        fn remove_peer_from_cache_does_what_it_says() {
            let cached_peer = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
            let mut bootstrap_cache = test_bootstrap_cache();
            bootstrap_cache.put(cached_peer);
            let mut core = test_core(bootstrap_cache);
            let poll = unwrap!(Poll::new());

            let (our_ci, our_sk) = test_priv_conn_info();
            let (their_ci, _) = test_priv_conn_info();
            let their_ci = their_ci.to_pub_connection_info();

            let (event_tx, _event_rx) = get_event_sender();
            unwrap!(Connect::start(
                &mut core,
                &poll,
                our_ci,
                their_ci.clone(),
                [1; 32],
                event_tx,
                &our_sk,
                Default::default(),
            ));

            let connect_state_token = Token(0);
            let state = unwrap!(core.get_state(connect_state_token));
            let mut state = state.borrow_mut();
            let connect_state = unwrap!(state.as_any().downcast_mut::<Connect>());

            connect_state.remove_peer_from_cache(&mut core, &cached_peer);

            let cached_peers = core.user_data().bootstrap_cache.peers();
            assert!(cached_peers.is_empty());
        }
    }
}
