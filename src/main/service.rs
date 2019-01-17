// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::{
    self, BootstrapperRole, CoreMessage, CrustUser, NameHash, PeerInfo, Uid, HASH_SIZE,
};
use crate::main::bootstrap::Cache as BootstrapCache;
use crate::main::config_handler::{self, Config};
use crate::main::{
    ActiveConnection, Bootstrap, ConfigRefresher, ConfigWrapper, Connect, ConnectionId,
    ConnectionInfoResult, ConnectionListener, CrustData, CrustError, Event, EventLoop,
    EventLoopCore, PrivConnectionInfo, PubConnectionInfo,
};
use crate::nat::{ip_addr_is_global, MappedTcpSocket, MappingContext};
use crate::service_discovery::ServiceDiscovery;
use mio::{Poll, Token};
use safe_crypto::{self, gen_encrypt_keypair, PublicEncryptKey, SecretEncryptKey};
use socket_collection::Priority;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{mpsc, Arc};

/// Reserved mio `Token` values for Crust speficic events.
#[derive(Debug, PartialEq)]
#[repr(usize)]
enum EventToken {
    Bootstrap,
    ServiceDiscovery,
    Listener,
    ConfigRefresher,
    Unreserved,
}

impl From<EventToken> for Token {
    fn from(token: EventToken) -> Token {
        Token(token as usize)
    }
}

const SERVICE_DISCOVERY_DEFAULT_PORT: u16 = 5484;

const DISABLE_NAT: bool = true;

/// A structure representing all the Crust services. This is the main object through which crust is
/// used.
///
/// You can construct `Service` using [`try_new`] which searches for config file in default location
/// or [`with_config`], if you want to provide an in memory config.
///
/// In the terms of networking `Service` exposes both server and client functionality. Meaning
/// it will listen for incoming connections and establish ones itself.
///
/// You can use `Service` to connect with remote peers. There's two ways to do this:
///
/// 1. [`bootstrap`] to some known peers or the ones discovered on LAN,
/// 2. [`connect`] to the peer whose contacts you already have.
///
/// You can also configure `Service` listener to only accept peers that have public IP address
/// and are reachable directly. This is called external reachability test which is configured
/// with [`set_ext_reachability_test`].
///
/// You also have to explicilty enable connection listening:
///
/// 1. to accept bootstrapping peers, call [`set_accept_bootstrap`],
/// 2. to accept incoming connections via [`connect`], call [`start_listening_tcp`],
/// 2. to accept incoming peers via service discovery on LAN, call [`set_service_discovery_listen`].
///
/// ## Implementation Notes
///
/// It might be worthy knowing how `Service` operates under the hood. `Service::with_config()`
/// creates a separate thread and spawns mio based event loop on it. This event loop is used
/// for all networking operations.
///
/// `Service` is just a handle to interface with the underlying event loop:
///
/// 1. We use `Service` to spawn functions on an event loop, e.g. connect to some peer.
/// 2. The actual Crust operation (connection, bootstrap, etc.) is executed in parallel on a
///    dedicated thread.
/// 3. When something happens, successful/failed connection, etc., `Service` emits events through
///    the `CrustEventSender`.
///
/// [`try_new`]: struct.Service.html#method.try_new
/// [`with_config`]: struct.Service.html#method.with_config
/// [`connect`]: struct.Service.html#method.connect
/// [`bootstrap`]: struct.Service.html#method.start_bootstrap
/// [`set_accept_bootstrap`]: struct.Service.html#method.set_accept_bootstrap
/// [`start_listening_tcp`]: struct.Service.html#method.set_listening_tcp
/// [`set_service_discovery_listen`]: struct.Service.html#method.set_service_discovery_listen
/// [`set_ext_reachability_test`]: struct.Service.html#method.set_ext_reachability_test
pub struct Service<UID: Uid> {
    event_tx: crate::CrustEventSender<UID>,
    // TODO(povilas): see if we can eliminate Arc by moving MappingContext into CrustData
    // stored in Core
    mc: Arc<MappingContext>,
    el: EventLoop<UID>,
    name_hash: NameHash,
    our_uid: UID,
    our_pk: PublicEncryptKey,
    our_sk: SecretEncryptKey,
}

impl<UID: Uid> Service<UID> {
    /// Construct a service. `event_tx` is the sending half of the channel which crust will send
    /// notifications on. Can fail, if can't read config file successfully.
    pub fn try_new(event_tx: crate::CrustEventSender<UID>, our_uid: UID) -> crate::Res<Self> {
        Service::with_config(event_tx, config_handler::read_config_file()?, our_uid)
    }

    /// Constructs a service with the given config. User needs to create an asynchronous channel,
    /// and provide the sender half to this method. Receiver will receive all `Event`s from this
    /// library.
    pub fn with_config(
        event_tx: crate::CrustEventSender<UID>,
        config: Config,
        our_uid: UID,
    ) -> crate::Res<Self> {
        safe_crypto::init()?;

        let name_hash = name_hash(&config.network_name);

        let mut mc = MappingContext::try_new()?;
        mc.add_peer_stuns(config.hard_coded_contacts.iter().cloned());

        let bootstrap_cache_file = config.bootstrap_cache_name.clone();
        let el = common::spawn_event_loop(
            EventToken::Unreserved as usize,
            Some(&format!("{:?}", our_uid)),
            move || {
                let cache = BootstrapCache::new(bootstrap_cache_file);
                cache.read_file();
                let mut user_data = CrustData::new(cache);
                user_data.config = ConfigWrapper::new(config);
                user_data
            },
        )?;
        trace!("Event loop started");

        // TODO(povilas): get from constructor params
        let (our_pk, our_sk) = gen_encrypt_keypair();
        let service = Service {
            event_tx,
            mc: Arc::new(mc),
            el,
            name_hash,
            our_uid,
            our_pk,
            our_sk,
        };

        service.start_config_refresher()?;

        Ok(service)
    }

    fn start_config_refresher(&self) -> crate::Res<()> {
        let (tx, rx) = mpsc::channel();
        self.post(move |core, _| {
            if core.get_state(EventToken::ConfigRefresher.into()).is_none() {
                let _ = tx.send(ConfigRefresher::start(
                    core,
                    EventToken::ConfigRefresher.into(),
                ));
            }
            let _ = tx.send(Ok(()));
        })?;
        rx.recv()?
    }

    /// Allow (or disallow) peers from bootstrapping off us.
    pub fn set_accept_bootstrap(&self, accept: bool) -> crate::Res<()> {
        let (tx, rx) = mpsc::channel();
        let _ = self.post(move |core, _| {
            let state = match core.get_state(EventToken::Listener.into()) {
                Some(state) => state,
                None => {
                    let _ = tx.send(Err(CrustError::ListenerNotIntialised));
                    return;
                }
            };
            let mut state = state.borrow_mut();
            let listener = match state.as_any().downcast_mut::<ConnectionListener<UID>>() {
                Some(l) => l,
                None => {
                    warn!("Token reserved for ConnectionListener has something else.");
                    return;
                }
            };
            listener.set_accept_bootstrap(accept);
            let _ = tx.send(Ok(()));
        });

        rx.recv()?
    }

    /// Enables/disables peer external reachability test.
    /// When a new peer connects to us, `Service` listener can be configured to test if this
    /// peer is reachable directly over it's public IP. If external reachability test is enabled,
    /// and peer is not reachable, then we discard such connection.
    pub fn set_ext_reachability_test(&self, accept: bool) -> crate::Res<()> {
        let (tx, rx) = mpsc::channel();
        let _ = self.post(move |core, _| {
            let state = match core.get_state(EventToken::Listener.into()) {
                Some(state) => state,
                None => {
                    let _ = tx.send(Err(CrustError::ListenerNotIntialised));
                    return;
                }
            };
            let mut state = state.borrow_mut();
            let listener = match state.as_any().downcast_mut::<ConnectionListener<UID>>() {
                Some(l) => l,
                None => {
                    warn!("Token reserved for ConnectionListener has something else.");
                    return;
                }
            };
            listener.set_ext_reachability_test(accept);
            let _ = tx.send(Ok(()));
        });

        rx.recv()?
    }

    /// Initialises Service Discovery module and starts listening for responses to our beacon
    /// broadcasts.
    pub fn start_service_discovery(&mut self) {
        let our_pk = self.our_pk;
        let _ = self.post(move |core, poll| {
            let config = &core.user_data().config.cfg;
            let remote_port = config
                .service_discovery_port
                .unwrap_or(SERVICE_DISCOVERY_DEFAULT_PORT);
            let listener_port = config
                .service_discovery_listener_port
                .unwrap_or(remote_port);

            if core
                .get_state(EventToken::ServiceDiscovery.into())
                .is_none()
            {
                if let Err(e) = ServiceDiscovery::start(
                    core,
                    poll,
                    EventToken::ServiceDiscovery.into(),
                    listener_port,
                    remote_port,
                    our_pk,
                ) {
                    info!("Could not start ServiceDiscovery: {:?}", e);
                }
            }
        });
    }

    /// Enable (or disable) listening and responding to peers searching for us. This can be used to
    /// allow others to discover us on the local network.
    pub fn set_service_discovery_listen(&self, listen: bool) {
        let _ = self.post(move |core, _| {
            let state = match core.get_state(EventToken::ServiceDiscovery.into()) {
                Some(state) => state,
                None => return,
            };
            let mut state = state.borrow_mut();
            let service_discovery = match state
                .as_any()
                .downcast_mut::<ServiceDiscovery<CrustData<UID>>>()
            {
                Some(sd) => sd,
                None => {
                    warn!("Token reserved for ServiceDiscovery has something else.");
                    return;
                }
            };
            service_discovery.set_listen(listen);
        });
    }

    /// Checks if given peer was connected, if so, returns it's address together with a flag
    /// indicating whether it was hard coded in config or not.
    fn get_peer_socket_addr(&self, peer_uid: &UID) -> crate::Res<(SocketAddr, bool)> {
        let peer_uid = *peer_uid;
        let (tx, rx) = mpsc::channel();

        let _ = self.post(move |core, _| {
            let token = match core.user_data().connections.get(&peer_uid) {
                Some(&ConnectionId {
                    active_connection: Some(token),
                    ..
                }) => token,
                _ => {
                    let _ = tx.send(None);
                    return;
                }
            };
            let state = match core.get_state(token) {
                Some(state) => state,
                None => {
                    let _ = tx.send(None);
                    return;
                }
            };
            match state
                .borrow_mut()
                .as_any()
                .downcast_mut::<ActiveConnection<UID>>()
            {
                Some(active_connection) => {
                    let config = &core.user_data().config.cfg;
                    let peer_addr_res = active_connection.peer_addr().map(|peer_addr| {
                        let was_hard_coded = config
                            .hard_coded_contacts
                            .iter()
                            .any(|peer| peer.addr.ip() == peer_addr.ip());
                        (peer_addr, was_hard_coded)
                    });
                    let _ = tx.send(Some(peer_addr_res));
                }
                None => {
                    debug!("Expected token {:?} to be ActiveConnection", token);
                    let _ = tx.send(None);
                }
            };
        });

        match rx.recv() {
            Ok(Some(ip)) => ip,
            Ok(None) => Err(CrustError::PeerNotFound),
            Err(e) => Err(CrustError::ChannelRecv(e)),
        }
    }

    /// Return the ip address of the peer.
    pub fn get_peer_ip_addr(&self, peer_uid: &UID) -> crate::Res<IpAddr> {
        self.get_peer_socket_addr(peer_uid).map(|(s, _)| s.ip())
    }

    /// Returns whether the given peer's IP is in the config file's hard-coded contacts list.
    pub fn is_peer_hard_coded(&self, peer_uid: &UID) -> bool {
        self.get_peer_socket_addr(peer_uid)
            .map(|(_, hard_coded)| hard_coded)
            .unwrap_or(false)
    }

    // TODO temp remove
    /// Check if we have peers on LAN
    pub fn has_peers_on_lan(&self) -> bool {
        use std::thread;
        use std::time::Duration;

        let (obs, rx) = mpsc::channel();
        let _ = self.post(move |core, _| {
            let state = match core.get_state(EventToken::ServiceDiscovery.into()) {
                Some(state) => state,
                None => return,
            };
            let mut state = state.borrow_mut();
            let service_discovery = match state
                .as_any()
                .downcast_mut::<ServiceDiscovery<CrustData<UID>>>()
            {
                Some(sd) => sd,
                None => {
                    warn!("Token reserved for ServiceDiscovery has something else.");
                    return;
                }
            };
            service_discovery.register_observer(obs);
            let _ = service_discovery.seek_peers();
        });

        thread::sleep(Duration::from_secs(1));
        rx.try_recv().is_ok()
    }

    /// Start the bootstrapping procedure. It will auto terminate after indicating success or
    /// failure via the event channel.
    pub fn start_bootstrap(
        &mut self,
        blacklist: HashSet<SocketAddr>,
        crust_user: CrustUser,
    ) -> crate::Res<()> {
        let our_uid = self.our_uid;
        let name_hash = self.name_hash;
        let our_pk = self.our_pk;
        let our_sk = self.our_sk.clone();
        let event_tx = self.event_tx.clone();

        self.post(move |core, poll| {
            let bootstrapper_role = match crust_user {
                CrustUser::Node => BootstrapperRole::Node(our_global_listener_addrs(core)),
                CrustUser::Client => BootstrapperRole::Client,
            };
            if core.get_state(EventToken::Bootstrap.into()).is_none() {
                if let Err(e) = Bootstrap::start(
                    core,
                    poll,
                    name_hash,
                    our_uid,
                    bootstrapper_role,
                    blacklist,
                    EventToken::Bootstrap.into(),
                    EventToken::ServiceDiscovery.into(),
                    event_tx.clone(),
                    our_pk,
                    &our_sk,
                ) {
                    error!("Could not bootstrap: {:?}", e);
                    let _ = event_tx.send(Event::BootstrapFailed);
                }
            }
        })
    }

    /// Stop the bootstraping procedure explicitly
    pub fn stop_bootstrap(&mut self) -> crate::Res<()> {
        self.post(move |core, poll| {
            if let Some(state) = core.get_state(EventToken::Bootstrap.into()) {
                state.borrow_mut().terminate(core, poll);
            }
        })
    }

    /// Starts accepting TCP connections. This is persistant until it errors out or is stopped
    /// explicitly.
    pub fn start_listening_tcp(&mut self) -> crate::Res<()> {
        let mc = self.mc.clone();
        let our_uid = self.our_uid;
        let name_hash = self.name_hash;
        let event_tx = self.event_tx.clone();

        let our_pk = self.our_pk;
        let our_sk = self.our_sk.clone();
        self.post(move |core, poll| {
            let config = &core.user_data().config.cfg;
            let port = config.tcp_acceptor_port.unwrap_or(0);
            let force_include_port = config.force_acceptor_port_in_ext_ep;

            if core.get_state(EventToken::Listener.into()).is_none() {
                ConnectionListener::start(
                    core,
                    poll,
                    None,
                    port,
                    force_include_port,
                    our_uid,
                    name_hash,
                    mc,
                    EventToken::Listener.into(),
                    event_tx,
                    our_pk,
                    our_sk,
                );
            }
        })
    }

    /// Stops Listener explicitly and stops accepting TCP connections.
    pub fn stop_tcp_listener(&mut self) -> crate::Res<()> {
        self.post(move |core, poll| {
            if let Some(state) = core.get_state(EventToken::Listener.into()) {
                state.borrow_mut().terminate(core, poll);
            }
        })
    }

    /// Connect to a peer. To call this method you must follow these steps:
    ///  * Generate a `PrivConnectionInfo` via `Service::prepare_connection_info`.
    ///  * Create a `PubConnectionInfo` via `PrivConnectionInfo::to_pub_connection_info`.
    ///  * Swap `PubConnectionInfo`s out-of-band with the peer you are connecting to.
    ///  * Call `Service::connect` using your `PrivConnectionInfo` and the `PubConnectionInfo`
    ///    obtained from the peer
    pub fn connect(
        &self,
        our_ci: PrivConnectionInfo<UID>,
        mut their_ci: PubConnectionInfo<UID>,
    ) -> crate::Res<()> {
        if their_ci.id == self.our_uid {
            debug!(
                "Requested connect to {:?}, which is our peer ID",
                their_ci.id
            );
            return Err(CrustError::RequestedConnectToSelf);
        }

        let event_tx = self.event_tx.clone();
        let our_nh = self.name_hash;
        let our_pk = self.our_pk;
        let our_sk = self.our_sk.clone();

        self.post(move |core, poll| {
            if let Some(ref whitelisted_node_ips) = core.user_data().config.cfg.whitelisted_node_ips
            {
                let their_direct = their_ci
                    .for_direct
                    .drain(..)
                    .filter(|s| whitelisted_node_ips.contains(&s.ip()))
                    .collect();
                their_ci.for_direct = their_direct;
            }

            if core.user_data().connections.contains_key(&their_ci.id) {
                debug!(
                    "Already connected OR already in process of connecting to {:?}",
                    their_ci.id
                );
                return;
            }
            let _ = Connect::start(
                core,
                poll,
                our_ci,
                their_ci,
                our_nh,
                event_tx,
                our_pk,
                &our_sk,
                our_global_listener_addrs(core),
            );
        })?;

        Ok(())
    }

    /// Disconnect from the given peer and returns whether there was a connection at all.
    pub fn disconnect(&self, peer_uid: &UID) -> bool {
        let peer_uid = *peer_uid;
        let (tx, rx) = mpsc::channel();

        let _ = self.post(move |core, poll| {
            if let Some(&ConnectionId {
                active_connection: Some(token),
                ..
            }) = core.user_data().connections.get(&peer_uid)
            {
                if let Some(state) = core.get_state(token) {
                    state.borrow_mut().terminate(core, poll);
                }
                let _ = tx.send(true);
            } else {
                let _ = tx.send(false);
            }
        });

        rx.recv().unwrap_or(false)
    }

    /// Send data to a peer.
    pub fn send(&self, peer_uid: &UID, msg: Vec<u8>, priority: Priority) -> crate::Res<()> {
        let peer_uid = *peer_uid;
        let (tx, rx) = mpsc::channel();

        let res = self.post(move |core, poll| {
            if let Some(&ConnectionId {
                active_connection: Some(token),
                ..
            }) = core.user_data().connections.get(&peer_uid)
            {
                if let Some(state) = core.get_state(token) {
                    state.borrow_mut().write(core, poll, msg, priority);
                }
                let _ = tx.send(Ok(()));
            } else {
                let _ = tx.send(Err(CrustError::PeerNotFound));
            }
        });
        res.and_then(|_| {
            rx.recv()
                .map_err(CrustError::ChannelRecv)
                .and_then(|res| res)
        })
    }

    /// Generate connection info. The connection info is returned via the `ConnectionInfoPrepared`
    /// event on the event channel. Calling this method is the first step of connecting to another
    /// peer, see `Service::connect` for more info.
    // TODO: immediate return in case of sender.send() returned with NotificationError
    pub fn prepare_connection_info(&self, result_token: u32) {
        let our_pk = self.our_pk;
        let our_sk = self.our_sk.clone();
        let our_uid = self.our_uid;
        let event_tx = self.event_tx.clone();

        let post_res = if DISABLE_NAT {
            self.post(move |core, _poll| {
                let our_listeners = core
                    .user_data()
                    .our_listeners
                    .iter()
                    .map(|peer| peer.addr)
                    .collect();
                let event = Event::ConnectionInfoPrepared(ConnectionInfoResult {
                    result_token,
                    result: Ok(PrivConnectionInfo {
                        id: our_uid,
                        for_direct: our_listeners,
                        our_pk,
                    }),
                });
                let _ = event_tx.send(event);
            })
        } else {
            let mc = self.mc.clone();
            self.post(move |core, poll| {
                let our_listeners = core
                    .user_data()
                    .our_listeners
                    .iter()
                    .map(|peer| peer.addr)
                    .collect();
                let event_tx_clone = event_tx.clone();
                match MappedTcpSocket::<_, UID, _>::start(
                    core,
                    poll,
                    0,
                    &mc,
                    our_pk,
                    &our_sk,
                    move |_, _, _socket, _addrs| {
                        let event_tx = event_tx_clone;
                        let event = Event::ConnectionInfoPrepared(ConnectionInfoResult {
                            result_token,
                            result: Ok(PrivConnectionInfo {
                                id: our_uid,
                                for_direct: our_listeners,
                                our_pk,
                            }),
                        });
                        let _ = event_tx.send(event);
                    },
                ) {
                    Ok(()) => (),
                    Err(e) => {
                        debug!("Error mapping tcp socket: {}", e);
                        let _ =
                            event_tx.send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                                result_token,
                                result: Err(From::from(e)),
                            }));
                    }
                };
            })
        };
        if let Err(e) = post_res {
            let _ = self
                .event_tx
                .send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                    result_token,
                    result: Err(e),
                }));
        }
    }

    /// Check if we are connected to the given peer
    pub fn is_connected(&self, peer_uid: &UID) -> bool {
        let peer_uid = *peer_uid;
        let (tx, rx) = mpsc::channel();

        let _ = self.post(move |core, _| {
            let connected = match core.user_data().connections.get(&peer_uid) {
                Some(&ConnectionId {
                    active_connection: Some(_),
                    ..
                }) => true,
                _ => false,
            };
            let _ = tx.send(connected);
        });

        rx.recv().unwrap_or(false)
    }

    /// Returns our ID.
    pub fn id(&self) -> UID {
        self.our_uid
    }

    /// Returns service public key used to encrypt traffic.
    pub fn pub_key(&self) -> PublicEncryptKey {
        self.our_pk
    }

    /// Returns a list of peers stored in bootstrap cache.
    pub fn bootstrap_cached_peers(&self) -> crate::Res<HashSet<PeerInfo>> {
        let (tx, rx) = mpsc::channel();
        let _ = self.post(move |core, _| {
            let cached_peers = core.user_data().bootstrap_cache.peers();
            let _ = tx.send(cached_peers);
        });
        rx.recv().map_err(CrustError::ChannelRecv)
    }

    fn post<F>(&self, f: F) -> crate::Res<()>
    where
        F: FnOnce(&mut EventLoopCore<UID>, &Poll) + Send + 'static,
    {
        self.el.send(CoreMessage::new(f))?;
        Ok(())
    }
}

fn our_global_listener_addrs<UID: Uid>(core: &EventLoopCore<UID>) -> HashSet<SocketAddr> {
    core.user_data()
        .our_listeners
        .iter()
        .map(|peer| peer.addr)
        .filter(|addr| ip_addr_is_global(&addr.ip()))
        .collect()
}

/// Returns a hash of the network name.
fn name_hash(network_name: &Option<String>) -> NameHash {
    trace!("Network name: {:?}", network_name);
    match *network_name {
        Some(ref name) => safe_crypto::hash(name.as_bytes()),
        None => [0; HASH_SIZE],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::CrustUser;
    use crate::main::{self, Event};
    use crate::tests::{get_event_sender, timebomb, UniqueId};
    use crate::CrustError;
    use maidsafe_utilities;
    use maidsafe_utilities::thread::Joiner;
    use rand;
    use std::collections::{hash_map, HashMap};
    use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
    use std::sync::mpsc::Receiver;
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    type Service = super::Service<UniqueId>;
    type PrivConnectionInfo = main::PrivConnectionInfo<UniqueId>;
    type PubConnectionInfo = main::PubConnectionInfo<UniqueId>;

    #[test]
    fn connect_self() {
        timebomb(Duration::from_secs(30), || {
            let (event_tx, event_rx) = get_event_sender();
            let mut service = unwrap!(Service::try_new(event_tx, rand::random()));

            unwrap!(service.start_listening_tcp());
            expect_event!(event_rx, Event::ListenerStarted(_));

            service.prepare_connection_info(0);

            let conn_info_result = expect_event!(event_rx,
                                                 Event::ConnectionInfoPrepared(result) => result);

            let priv_info = unwrap!(conn_info_result.result);
            let pub_info = priv_info.to_pub_connection_info();

            match service.connect(priv_info, pub_info) {
                Err(CrustError::RequestedConnectToSelf) => (),
                Ok(()) | Err(..) => panic!("Expected CrustError::RequestedConnectedToSelf"),
            }
        })
    }

    #[test]
    fn direct_connect_two_peers() {
        timebomb(Duration::from_secs(30), || {
            let (event_tx_0, event_rx_0) = get_event_sender();
            let mut service_0 = unwrap!(Service::try_new(event_tx_0, rand::random()));

            unwrap!(service_0.start_listening_tcp());
            expect_event!(event_rx_0, Event::ListenerStarted(_));
            unwrap!(service_0.set_ext_reachability_test(false));

            let (event_tx_1, event_rx_1) = get_event_sender();
            let mut service_1 = unwrap!(Service::try_new(event_tx_1, rand::random()));

            unwrap!(service_1.start_listening_tcp());
            expect_event!(event_rx_1, Event::ListenerStarted(_));
            unwrap!(service_1.set_ext_reachability_test(false));

            connect(&service_0, &event_rx_0, &service_1, &event_rx_1);
            exchange_messages(&service_0, &event_rx_0, &service_1, &event_rx_1);
        })
    }

    #[test]
    #[ignore]
    fn rendezvous_connect_two_peers() {
        unwrap!(maidsafe_utilities::log::init(true));
        timebomb(Duration::from_secs(30), || {
            let (event_tx_0, event_rx_0) = get_event_sender();
            let service_0 = unwrap!(Service::try_new(event_tx_0, rand::random()));

            let (event_tx_1, event_rx_1) = get_event_sender();
            let service_1 = unwrap!(Service::try_new(event_tx_1, rand::random()));

            connect(&service_0, &event_rx_0, &service_1, &event_rx_1);
            debug!("Exchanging messages ...");
            exchange_messages(&service_0, &event_rx_0, &service_1, &event_rx_1);
        });
        thread::sleep(Duration::from_secs(1));
    }

    fn connect(
        service_0: &Service,
        event_rx_0: &Receiver<Event<UniqueId>>,
        service_1: &Service,
        event_rx_1: &Receiver<Event<UniqueId>>,
    ) {
        service_0.prepare_connection_info(0);
        service_1.prepare_connection_info(0);

        let conn_info_result_0 = expect_event!(event_rx_0,
                                               Event::ConnectionInfoPrepared(result) => result);
        let conn_info_result_1 = expect_event!(event_rx_1,
                                               Event::ConnectionInfoPrepared(result) => result);

        let priv_info_0 = unwrap!(conn_info_result_0.result);
        let priv_info_1 = unwrap!(conn_info_result_1.result);
        let pub_info_0 = priv_info_0.to_pub_connection_info();
        let pub_info_1 = priv_info_1.to_pub_connection_info();

        unwrap!(service_0.connect(priv_info_0, pub_info_1));
        unwrap!(service_1.connect(priv_info_1, pub_info_0));

        expect_event!(event_rx_0, Event::ConnectSuccess(id) => assert_eq!(id, service_1.id()));
        expect_event!(event_rx_1, Event::ConnectSuccess(id) => assert_eq!(id, service_0.id()));
    }

    fn exchange_messages(
        service_0: &Service,
        event_rx_0: &Receiver<Event<UniqueId>>,
        service_1: &Service,
        event_rx_1: &Receiver<Event<UniqueId>>,
    ) {
        use rand;
        use std::iter;

        let id_0 = service_0.id();
        let id_1 = service_1.id();

        let data_0: Vec<u8> = iter::repeat(()).take(32).map(|()| rand::random()).collect();
        let send_0 = data_0.clone();
        let data_1: Vec<u8> = iter::repeat(()).take(32).map(|()| rand::random()).collect();
        let send_1 = data_1.clone();

        unwrap!(service_0.send(&id_1, data_0, 0));
        unwrap!(service_1.send(&id_0, data_1, 0));

        let recv_1 = expect_event!(event_rx_0, Event::NewMessage(id, CrustUser::Node, recv) => {
            assert_eq!(id, id_1);
            recv
        });

        let recv_0 = expect_event!(event_rx_1, Event::NewMessage(id, CrustUser::Node, recv) => {
            assert_eq!(id, id_0);
            recv
        });

        assert_eq!(recv_0, send_0);
        assert_eq!(recv_1, send_1);
    }

    fn prepare_connection_info(
        service: &mut Service,
        event_rx: &Receiver<Event<UniqueId>>,
    ) -> PrivConnectionInfo {
        static TOKEN_COUNTER: AtomicUsize = ATOMIC_USIZE_INIT;
        let token = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed) as u32;

        service.prepare_connection_info(token);

        match unwrap!(event_rx.recv()) {
            Event::ConnectionInfoPrepared(cir) => {
                assert_eq!(cir.result_token, token);
                unwrap!(cir.result)
            }
            event => panic!("Received unexpected event: {:?}", event),
        }
    }

    #[test]
    #[ignore]
    fn sending_receiving_multiple_services() {
        const NUM_SERVICES: usize = 10;
        const MSG_SIZE: usize = 20 * 1024;
        const NUM_MSGS: usize = 100;

        struct TestNode {
            event_rx: Receiver<Event<UniqueId>>,
            service: Service,
            connection_id_rx: Receiver<PubConnectionInfo>,
            our_cis: Vec<PrivConnectionInfo>,
            our_index: usize,
        }

        impl TestNode {
            fn new_with_sender(index: usize) -> (Self, mpsc::Sender<PubConnectionInfo>) {
                let (event_sender, event_rx) = get_event_sender();
                let config = unwrap!(crate::main::config_handler::read_config_file());
                let mut service =
                    unwrap!(Service::with_config(event_sender, config, rand::random()));
                // Start listener so that the test works without hole punching.
                assert!(service.start_listening_tcp().is_ok());
                match unwrap!(event_rx.recv()) {
                    Event::ListenerStarted(_) => (),
                    m => panic!("Unexpected event: {:?}", m),
                }
                let (ci_tx, ci_rx) = mpsc::channel();
                (
                    TestNode {
                        event_rx,
                        service,
                        connection_id_rx: ci_rx,
                        our_cis: Vec::new(),
                        our_index: index,
                    },
                    ci_tx,
                )
            }

            fn make_connection_infos(&mut self, ci_txs: &[mpsc::Sender<PubConnectionInfo>]) {
                for (i, ci_tx) in ci_txs.iter().enumerate() {
                    if i == self.our_index {
                        continue;
                    }

                    let our_ci = prepare_connection_info(&mut self.service, &self.event_rx);
                    let their_ci = our_ci.to_pub_connection_info();
                    let _ = ci_tx.send(their_ci);
                    self.our_cis.push(our_ci);
                }
            }

            fn run(self, send_barrier: Arc<Barrier>, drop_barrier: Arc<Barrier>) -> Joiner {
                maidsafe_utilities::thread::named("run!", move || {
                    for (our_ci, their_ci) in self
                        .our_cis
                        .into_iter()
                        .zip(self.connection_id_rx.into_iter())
                    {
                        let _ = self.service.connect(our_ci, their_ci);
                    }
                    let mut their_ids = HashMap::new();
                    for _ in 0..NUM_SERVICES - 1 {
                        let their_id = match unwrap!(self.event_rx.recv()) {
                            Event::ConnectSuccess(their_id) => their_id,
                            m => panic!("Expected ConnectSuccess message. Got message {:?}", m),
                        };
                        if their_ids.insert(their_id, 0u32).is_some() {
                            panic!("Received two ConnectSuccess events for same peer!");
                        };
                    }

                    // Wait until all nodes have connected to each other before we start
                    // exchanging messages.
                    let _ = send_barrier.wait();

                    for their_id in their_ids.keys() {
                        for n in 0..NUM_MSGS {
                            let mut msg = Vec::with_capacity(MSG_SIZE);
                            for _ in 0..MSG_SIZE {
                                msg.push(n as u8);
                            }
                            let _ = self.service.send(their_id, msg, 0);
                        }
                    }

                    for _ in 0..((NUM_SERVICES - 1) * NUM_MSGS) {
                        match unwrap!(self.event_rx.recv()) {
                            Event::NewMessage(their_id, CrustUser::Node, msg) => {
                                let n = msg[0];
                                assert_eq!(msg.len(), MSG_SIZE);
                                for m in msg {
                                    assert_eq!(n, m);
                                }
                                match their_ids.entry(their_id) {
                                    hash_map::Entry::Occupied(mut oe) => {
                                        let next_msg = oe.get_mut();
                                        assert_eq!(*next_msg as u8, n);
                                        *next_msg += 1;
                                    }
                                    hash_map::Entry::Vacant(_) => panic!("impossible!"),
                                }
                            }
                            m => panic!("Unexpected msg receiving NewMessage: {:?}", m),
                        }
                    }

                    // Wait until all nodes have finished exchanging messages before we start
                    // disconnecting.
                    let _ = drop_barrier.wait();

                    drop(self.service);
                    match self.event_rx.recv() {
                        Ok(m) => match m {
                            Event::LostPeer(..) => (),
                            _ => panic!("Unexpected message when shutting down: {:?}", m),
                        },
                        Err(mpsc::RecvError) => (),
                    }
                })
            }
        }

        let mut test_nodes = Vec::new();
        let mut ci_txs = Vec::new();
        for i in 0..NUM_SERVICES {
            let (test_node, ci_tx) = TestNode::new_with_sender(i);
            test_nodes.push(test_node);
            ci_txs.push(ci_tx);
        }

        for test_node in &mut test_nodes {
            test_node.make_connection_infos(&ci_txs);
        }

        let send_barrier = Arc::new(Barrier::new(NUM_SERVICES));
        let drop_barrier = Arc::new(Barrier::new(NUM_SERVICES));
        let mut threads = Vec::new();
        for test_node in test_nodes {
            let send_barrier = send_barrier.clone();
            let drop_barrier = drop_barrier.clone();
            threads.push(test_node.run(send_barrier, drop_barrier));
        }

        // Wait one hundred millisecond per message
        // TODO(canndrew): drop this limit
        let timeout_ms = 10_000 * (NUM_MSGS * (NUM_SERVICES * (NUM_SERVICES - 1)) / 2) as u64;
        timebomb(Duration::from_millis(timeout_ms), move || {
            drop(threads);
        });
    }

    mod event_token {
        use super::*;

        #[test]
        fn tokens_start_with_number_0_and_increment_by_1() {
            let token = EventToken::Bootstrap;
            assert_eq!(Token::from(token), Token(0));

            let token = EventToken::ServiceDiscovery;
            assert_eq!(Token::from(token), Token(1));
        }
    }

    // TODO See how to now do this test
    // #[test]
    // fn bootstrap_with_whitelist_ip() {
    //     // Setup config with whitelisted IP
    //     let mut whitelisted_ips = HashSet::new();
    //     whitelisted_ips.insert(unwrap!(IpAddr::from_str("192.168.0.1")));

    //     let mut config = ::tests::utils::gen_config();
    //     config.whitelisted_node_ips = Some(whitelisted_ips);

    //     // Connect two peers
    //     let (event_tx_0, event_rx_0) = get_event_sender();
    //     let mut service_0 = unwrap!(Service::with_config(event_tx_0, config, rand::random()));

    //     unwrap!(service_0.start_listening_tcp());
    //     expect_event!(event_rx_0, Event::ListenerStarted(_));

    //     let (event_tx_1, event_rx_1) = get_event_sender();
    //     let mut service_1 = unwrap!(Service::try_new(event_tx_1, rand::random()));

    //     unwrap!(service_1.start_listening_tcp());
    //     expect_event!(event_rx_1, Event::ListenerStarted(_));

    //     connect(&service_0, &event_rx_0, &service_1, &event_rx_1);

    //     // Do checks
    //     assert_eq!(service_0.is_peer_whitelisted(&service_1.id()), true);
    //     assert_eq!(service_0.is_peer_whitelisted(&service_0.id()), false);

    //     // service_1 doesn't have a whitelist config, so all peers should be whitelisted
    //     assert_eq!(service_1.is_peer_whitelisted(&service_0.id()), true);
    //     assert_eq!(service_1.is_peer_whitelisted(&service_1.id()), true);
    // }
}
