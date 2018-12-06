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

use self::cache::Cache;
use self::try_peer::TryPeer;
use common::{
    BootstrapDenyReason, Core, CoreTimer, CrustUser, ExternalReachability, NameHash, State, Uid,
};
use main::{ActiveConnection, ConnectionMap, CrustConfig, CrustError, Event};
use mio::{Poll, Token};
use mio_extras::timer::Timeout;
use rand::{self, Rng};
use service_discovery::ServiceDiscovery;
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
    peers: Vec<SocketAddr>,
    blacklist: HashSet<SocketAddr>,
    name_hash: NameHash,
    ext_reachability: ExternalReachability,
    our_uid: UID,
    event_tx: ::CrustEventSender<UID>,
    sd_meta: Option<ServiceDiscMeta>,
    bs_timer: CoreTimer,
    bs_timeout: Timeout,
    cache: Cache,
    children: HashSet<Token>,
    self_weak: Weak<RefCell<Bootstrap<UID>>>,
}

impl<UID: Uid> Bootstrap<UID> {
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        name_hash: NameHash,
        ext_reachability: ExternalReachability,
        our_uid: UID,
        cm: ConnectionMap<UID>,
        config: CrustConfig,
        blacklist: HashSet<SocketAddr>,
        token: Token,
        service_discovery_token: Token,
        event_tx: ::CrustEventSender<UID>,
    ) -> ::Res<()> {
        let mut peers = Vec::with_capacity(MAX_CONTACTS_EXPECTED);

        let mut cache = Cache::new(&unwrap!(config.lock()).cfg.bootstrap_cache_name)?;
        peers.extend(cache.read_file());
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
            cache,
            children: HashSet::with_capacity(MAX_CONTACTS_EXPECTED),
            self_weak: Weak::new(),
        }));

        state.borrow_mut().self_weak = Rc::downgrade(&state);

        let _ = core.insert_state(token, state.clone());

        if state.borrow().sd_meta.is_none() {
            state.borrow_mut().begin_bootstrap(core, poll);
        }

        Ok(())
    }

    fn begin_bootstrap(&mut self, core: &mut Core, poll: &Poll) {
        let mut peers = mem::replace(&mut self.peers, Vec::new());
        peers.retain(|addr| !self.blacklist.contains(addr));
        if peers.is_empty() {
            let _ = self.event_tx.send(Event::BootstrapFailed);
            return self.terminate(core, poll);
        }
        rand::thread_rng().shuffle(&mut peers);

        for peer in peers {
            let self_weak = self.self_weak.clone();
            let finish = move |core: &mut Core, poll: &Poll, child, res| {
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
                Box::new(finish),
            ) {
                let _ = self.children.insert(child);
            }
        }
        self.maybe_terminate(core, poll);
    }

    fn handle_result(
        &mut self,
        core: &mut Core,
        poll: &Poll,
        child: Token,
        res: Result<(TcpSock, SocketAddr, UID), (SocketAddr, Option<BootstrapDenyReason>)>,
    ) {
        let _ = self.children.remove(&child);
        match res {
            Ok((socket, peer_addr, peer_id)) => {
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
                    Event::BootstrapConnect(peer_id, peer_addr),
                    self.event_tx.clone(),
                );
            }
            Err((bad_peer, opt_reason)) => {
                self.cache.remove_peer_acceptor(bad_peer);
                if let Some(reason) = opt_reason {
                    let mut is_err_fatal = true;
                    let err_msg = match reason {
                        BootstrapDenyReason::InvalidNameHash => "Network name mismatch.",
                        #[cfg_attr(rustfmt, rustfmt_skip)]
                        BootstrapDenyReason::FailedExternalReachability => {
                            "Bootstrappee node could not establish connection to us."
                        },
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
                            "Failed to Bootstrap with {}: ({:?}) {}",
                            bad_peer, reason, err_msg
                        );
                    }
                }
            }
        }
        self.maybe_terminate(core, poll);
    }

    fn maybe_terminate(&mut self, core: &mut Core, poll: &Poll) {
        if self.children.is_empty() {
            error!("Bootstrapper has no active children left - bootstrap has failed");
            self.terminate(core, poll);
            let _ = self.event_tx.send(Event::BootstrapFailed);
        }
    }

    fn terminate_children(&mut self, core: &mut Core, poll: &Poll) {
        for child in self.children.drain() {
            let child = match core.get_state(child) {
                Some(state) => state,
                None => continue,
            };

            child.borrow_mut().terminate(core, poll);
        }
    }
}

impl<UID: Uid> State for Bootstrap<UID> {
    fn timeout(&mut self, core: &mut Core, poll: &Poll, timer_id: u8) {
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

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
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
    rx: Receiver<Vec<SocketAddr>>,
    timeout: Timeout,
}

fn seek_peers(
    core: &mut Core,
    service_discovery_token: Token,
    token: Token,
) -> ::Res<(Receiver<Vec<SocketAddr>>, Timeout)> {
    if let Some(state) = core.get_state(service_discovery_token) {
        let mut state = state.borrow_mut();
        let state = unwrap!(state.as_any().downcast_mut::<ServiceDiscovery>());

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
