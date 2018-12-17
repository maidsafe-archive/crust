// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use common::{
    self, CoreMessage, CrustUser, ExternalReachability, NameHash, PeerInfo, Uid, HASH_SIZE,
};
use main::bootstrap::Cache as BootstrapCache;
use main::config_handler::{self, Config};
use main::{
    ActiveConnection, Bootstrap, ConfigRefresher, ConfigWrapper, Connect, ConnectionId,
    ConnectionInfoResult, ConnectionListener, ConnectionMap, CrustConfig, CrustError, Event,
    EventLoop, EventLoopCore, PrivConnectionInfo, PubConnectionInfo,
};
use mio::{Poll, Token};
use nat::{MappedTcpSocket, MappingContext};
use safe_crypto::{self, gen_encrypt_keypair, PublicEncryptKey, SecretEncryptKey};
use service_discovery::ServiceDiscovery;
use socket_collection::Priority;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::{mpsc, Arc, Mutex};

const BOOTSTRAP_TOKEN: Token = Token(0);
const SERVICE_DISCOVERY_TOKEN: Token = Token(1);
const LISTENER_TOKEN: Token = Token(2);
const CONFIG_REFRESHER_TOKEN: Token = Token(3);

const SERVICE_DISCOVERY_DEFAULT_PORT: u16 = 5484;

const DISABLE_NAT: bool = true;

/// A structure representing all the Crust services. This is the main object through which crust is
/// used.
pub struct Service<UID: Uid> {
    config: CrustConfig,
    cm: ConnectionMap<UID>,
    event_tx: ::CrustEventSender<UID>,
    mc: Arc<MappingContext>,
    el: EventLoop,
    name_hash: NameHash,
    our_uid: UID,
    our_listeners: Arc<Mutex<Vec<PeerInfo>>>,
    our_pk: PublicEncryptKey,
    our_sk: SecretEncryptKey,
}

impl<UID: Uid> Service<UID> {
    /// Construct a service. `event_tx` is the sending half of the channel which crust will send
    /// notifications on.
    pub fn new(event_tx: ::CrustEventSender<UID>, our_uid: UID) -> ::Res<Self> {
        Service::with_config(event_tx, config_handler::read_config_file()?, our_uid)
    }

    /// Constructs a service with the given config. User needs to create an asynchronous channel,
    /// and provide the sender half to this method. Receiver will receive all `Event`s from this
    /// library.
    pub fn with_config(
        event_tx: ::CrustEventSender<UID>,
        config: Config,
        our_uid: UID,
    ) -> ::Res<Self> {
        safe_crypto::init()?;

        let name_hash = name_hash(&config.network_name);

        // Form our initial contact info
        let our_listeners = Arc::new(Mutex::new(Vec::with_capacity(5)));
        let mut mc = MappingContext::new()?;
        mc.add_peer_stuns(config.hard_coded_contacts.iter().cloned());

        let bootstrap_cache_file = config.bootstrap_cache_name.clone();
        let el = common::spawn_event_loop(4, Some(&format!("{:?}", our_uid)), move || {
            match BootstrapCache::new(bootstrap_cache_file.as_ref()) {
                Ok(cache) => {
                    cache.read_file();
                    Some(cache)
                }
                Err(e) => {
                    error!("Failed to initialize bootstrap cache: {}", e);
                    None
                }
            }
        })?;
        trace!("Event loop started");

        // TODO(povilas): get from constructor params
        let (our_pk, our_sk) = gen_encrypt_keypair();
        let service = Service {
            cm: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(Mutex::new(ConfigWrapper::new(config))),
            event_tx,
            mc: Arc::new(mc),
            el,
            name_hash,
            our_uid,
            our_listeners,
            our_pk,
            our_sk,
        };

        service.start_config_refresher()?;

        Ok(service)
    }

    fn start_config_refresher(&self) -> ::Res<()> {
        let (tx, rx) = mpsc::channel();
        let config = self.config.clone();
        let cm = self.cm.clone();
        self.post(move |core, _| {
            if core.get_state(CONFIG_REFRESHER_TOKEN).is_none() {
                let _ = tx.send(ConfigRefresher::start(
                    core,
                    CONFIG_REFRESHER_TOKEN,
                    cm,
                    config,
                ));
            }
            let _ = tx.send(Ok(()));
        })?;
        rx.recv()?
    }

    /// Allow (or disallow) peers from bootstrapping off us.
    pub fn set_accept_bootstrap(&self, accept: bool) -> ::Res<()> {
        let (tx, rx) = mpsc::channel();
        let _ = self.post(move |core, _| {
            let state = match core.get_state(LISTENER_TOKEN) {
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

    /// Initialises Service Discovery module and starts listening for responses to our beacon
    /// broadcasts.
    pub fn start_service_discovery(&mut self) {
        let our_listeners = self.our_listeners.clone();
        let remote_port = unwrap!(self.config.lock())
            .cfg
            .service_discovery_port
            .unwrap_or(SERVICE_DISCOVERY_DEFAULT_PORT);
        let listener_port = unwrap!(self.config.lock())
            .cfg
            .service_discovery_listener_port
            .unwrap_or(remote_port);

        let our_pk = self.our_pk;
        let _ = self.post(move |core, poll| {
            if core.get_state(SERVICE_DISCOVERY_TOKEN).is_none() {
                if let Err(e) = ServiceDiscovery::start(
                    core,
                    poll,
                    our_listeners,
                    SERVICE_DISCOVERY_TOKEN,
                    listener_port,
                    remote_port,
                    our_pk,
                ) {
                    debug!("Could not start ServiceDiscovery: {:?}", e);
                }
            }
            () // Only to get rustfmt happy else it corrects it in a way it detects error
        });
    }

    /// Enable (or disable) listening and responding to peers searching for us. This can be used to
    /// allow others to discover us on the local network.
    pub fn set_service_discovery_listen(&self, listen: bool) {
        let _ = self.post(move |core, _| {
            let state = match core.get_state(SERVICE_DISCOVERY_TOKEN) {
                Some(state) => state,
                None => return,
            };
            let mut state = state.borrow_mut();
            let service_discovery = match state
                .as_any()
                .downcast_mut::<ServiceDiscovery<BootstrapCache>>()
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

    fn get_peer_socket_addr(&self, peer_uid: &UID) -> ::Res<SocketAddr> {
        let token = match unwrap!(self.cm.lock()).get(peer_uid) {
            Some(&ConnectionId {
                active_connection: Some(token),
                ..
            }) => token,
            _ => return Err(CrustError::PeerNotFound),
        };

        let (tx, rx) = mpsc::channel();

        let _ = self.post(move |core, _| {
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
                    let _ = tx.send(Some(active_connection.peer_addr()));
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
    pub fn get_peer_ip_addr(&self, peer_uid: &UID) -> ::Res<IpAddr> {
        self.get_peer_socket_addr(peer_uid).map(|s| s.ip())
    }

    /// Returns whether the given peer's IP is in the config file's hard-coded contacts list.
    pub fn is_peer_hard_coded(&self, peer_uid: &UID) -> bool {
        match self.get_peer_socket_addr(peer_uid) {
            Ok(s) => {
                let config = unwrap!(self.config.lock());
                config
                    .cfg
                    .hard_coded_contacts
                    .iter()
                    .any(|peer| peer.addr.ip() == s.ip())
            }
            Err(e) => {
                debug!("{}", e.description());
                false
            }
        }
    }

    // TODO temp remove
    /// Check if we have peers on LAN
    pub fn has_peers_on_lan(&self) -> bool {
        use std::thread;
        use std::time::Duration;

        let (obs, rx) = mpsc::channel();
        let _ = self.post(move |core, _| {
            let state = match core.get_state(SERVICE_DISCOVERY_TOKEN) {
                Some(state) => state,
                None => return,
            };
            let mut state = state.borrow_mut();
            let service_discovery = match state
                .as_any()
                .downcast_mut::<ServiceDiscovery<BootstrapCache>>()
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
    ) -> ::Res<()> {
        let config = self.config.clone();
        let our_uid = self.our_uid;
        let name_hash = self.name_hash;
        let our_pk = self.our_pk;
        let our_sk = self.our_sk.clone();
        let cm = self.cm.clone();
        let event_tx = self.event_tx.clone();
        let ext_reachability = match crust_user {
            CrustUser::Node => ExternalReachability::Required {
                direct_listeners: unwrap!(self.our_listeners.lock())
                    .iter()
                    .map(|peer| peer.addr)
                    .collect(),
            },
            CrustUser::Client => ExternalReachability::NotRequired,
        };

        self.post(move |core, poll| {
            if core.get_state(BOOTSTRAP_TOKEN).is_none() {
                if let Err(e) = Bootstrap::start(
                    core,
                    poll,
                    name_hash,
                    ext_reachability,
                    our_uid,
                    cm,
                    config,
                    blacklist,
                    BOOTSTRAP_TOKEN,
                    SERVICE_DISCOVERY_TOKEN,
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
    pub fn stop_bootstrap(&mut self) -> ::Res<()> {
        self.post(move |core, poll| {
            if let Some(state) = core.get_state(BOOTSTRAP_TOKEN) {
                state.borrow_mut().terminate(core, poll);
            }
        })
    }

    /// Starts accepting TCP connections. This is persistant until it errors out or is stopped
    /// explicitly.
    pub fn start_listening_tcp(&mut self) -> ::Res<()> {
        let cm = self.cm.clone();
        let mc = self.mc.clone();
        let config = self.config.clone();
        let port = unwrap!(self.config.lock())
            .cfg
            .tcp_acceptor_port
            .unwrap_or(0);
        let force_include_port = unwrap!(self.config.lock())
            .cfg
            .force_acceptor_port_in_ext_ep;
        let our_uid = self.our_uid;
        let name_hash = self.name_hash;
        let our_listeners = self.our_listeners.clone();
        let event_tx = self.event_tx.clone();

        let our_pk = self.our_pk;
        let our_sk = self.our_sk.clone();
        self.post(move |core, poll| {
            if core.get_state(LISTENER_TOKEN).is_none() {
                ConnectionListener::start(
                    core,
                    poll,
                    None,
                    port,
                    force_include_port,
                    our_uid,
                    name_hash,
                    cm,
                    config,
                    mc,
                    our_listeners,
                    LISTENER_TOKEN,
                    event_tx,
                    our_pk,
                    our_sk,
                );
            }
        })
    }

    /// Stops Listener explicitly and stops accepting TCP connections.
    pub fn stop_tcp_listener(&mut self) -> ::Res<()> {
        self.post(move |core, poll| {
            if let Some(state) = core.get_state(LISTENER_TOKEN) {
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
    ) -> ::Res<()> {
        if their_ci.id == self.our_uid {
            debug!(
                "Requested connect to {:?}, which is our peer ID",
                their_ci.id
            );
            return Err(CrustError::RequestedConnectToSelf);
        }

        if unwrap!(self.cm.lock()).contains_key(&their_ci.id) {
            debug!(
                "Already connected OR already in process of connecting to {:?}",
                their_ci.id
            );
            return Ok(());
        }

        {
            let guard = unwrap!(self.config.lock());
            if let Some(ref whitelisted_node_ips) = guard.cfg.whitelisted_node_ips {
                let their_direct = their_ci
                    .for_direct
                    .drain(..)
                    .filter(|s| whitelisted_node_ips.contains(&s.ip()))
                    .collect();
                their_ci.for_direct = their_direct;
            }
        }

        let event_tx = self.event_tx.clone();
        let cm = self.cm.clone();
        let our_nh = self.name_hash;
        let our_pk = self.our_pk;
        let our_sk = self.our_sk.clone();

        self.post(move |core, poll| {
            let _ = Connect::start(
                core, poll, our_ci, their_ci, cm, our_nh, event_tx, our_pk, &our_sk,
            );
        })?;

        Ok(())
    }

    /// Disconnect from the given peer and returns whether there was a connection at all.
    pub fn disconnect(&self, peer_uid: &UID) -> bool {
        let token = match unwrap!(self.cm.lock()).get(peer_uid) {
            Some(&ConnectionId {
                active_connection: Some(token),
                ..
            }) => token,
            _ => return false,
        };

        let _ = self.post(move |core, poll| {
            if let Some(state) = core.get_state(token) {
                state.borrow_mut().terminate(core, poll);
            }
        });

        true
    }

    /// Send data to a peer.
    pub fn send(&self, peer_uid: &UID, msg: Vec<u8>, priority: Priority) -> ::Res<()> {
        let token = match unwrap!(self.cm.lock()).get(peer_uid) {
            Some(&ConnectionId {
                active_connection: Some(token),
                ..
            }) => token,
            _ => return Err(CrustError::PeerNotFound),
        };

        self.post(move |core, poll| {
            if let Some(state) = core.get_state(token) {
                state.borrow_mut().write(core, poll, msg, priority);
            }
        })
    }

    /// Generate connection info. The connection info is returned via the `ConnectionInfoPrepared`
    /// event on the event channel. Calling this method is the first step of connecting to another
    /// peer, see `Service::connect` for more info.
    // TODO: immediate return in case of sender.send() returned with NotificationError
    pub fn prepare_connection_info(&self, result_token: u32) {
        let our_listeners = unwrap!(self.our_listeners.lock())
            .iter()
            .map(|peer| peer.addr)
            .collect();
        let our_pk = self.our_pk;
        let our_sk = self.our_sk.clone();

        if DISABLE_NAT {
            let event = Event::ConnectionInfoPrepared(ConnectionInfoResult {
                result_token,
                result: Ok(PrivConnectionInfo {
                    id: self.our_uid,
                    for_direct: our_listeners,
                    our_pk,
                }),
            });
            let _ = self.event_tx.send(event);
        } else {
            let event_tx = self.event_tx.clone();
            let our_uid = self.our_uid;
            let mc = self.mc.clone();
            if let Err(e) = self.post(move |core, poll| {
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
            }) {
                let _ = self
                    .event_tx
                    .send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                        result_token,
                        result: Err(e),
                    }));
            }
        }
    }

    /// Check if we are connected to the given peer
    pub fn is_connected(&self, peer_uid: &UID) -> bool {
        match unwrap!(self.cm.lock()).get(peer_uid) {
            Some(&ConnectionId {
                active_connection: Some(_),
                ..
            }) => true,
            _ => false,
        }
    }

    /// Returns our ID.
    pub fn id(&self) -> UID {
        self.our_uid
    }

    /// Returns service public key used to encrypt traffic.
    pub fn pub_key(&self) -> PublicEncryptKey {
        self.our_pk
    }

    fn post<F>(&self, f: F) -> ::Res<()>
    where
        F: FnOnce(&mut EventLoopCore, &Poll) + Send + 'static,
    {
        self.el.send(CoreMessage::new(f))?;
        Ok(())
    }
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
    use common::CrustUser;
    use maidsafe_utilities;
    use maidsafe_utilities::thread::Joiner;
    use main::{self, Event};
    use rand;
    use std::collections::{hash_map, HashMap};
    use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
    use std::sync::mpsc::Receiver;
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::Duration;
    use tests::{get_event_sender, timebomb, UniqueId};
    use CrustError;

    type Service = super::Service<UniqueId>;
    type PrivConnectionInfo = main::PrivConnectionInfo<UniqueId>;
    type PubConnectionInfo = main::PubConnectionInfo<UniqueId>;

    #[test]
    fn connect_self() {
        timebomb(Duration::from_secs(30), || {
            let (event_tx, event_rx) = get_event_sender();
            let mut service = unwrap!(Service::new(event_tx, rand::random()));

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
            let mut service_0 = unwrap!(Service::new(event_tx_0, rand::random()));

            unwrap!(service_0.start_listening_tcp());
            expect_event!(event_rx_0, Event::ListenerStarted(_));

            let (event_tx_1, event_rx_1) = get_event_sender();
            let mut service_1 = unwrap!(Service::new(event_tx_1, rand::random()));

            unwrap!(service_1.start_listening_tcp());
            expect_event!(event_rx_1, Event::ListenerStarted(_));

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
            let service_0 = unwrap!(Service::new(event_tx_0, rand::random()));

            let (event_tx_1, event_rx_1) = get_event_sender();
            let service_1 = unwrap!(Service::new(event_tx_1, rand::random()));

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
            fn new(index: usize) -> (TestNode, mpsc::Sender<PubConnectionInfo>) {
                let (event_sender, event_rx) = get_event_sender();
                let config = unwrap!(::main::config_handler::read_config_file());
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
            let (test_node, ci_tx) = TestNode::new(i);
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
    //     let mut service_1 = unwrap!(Service::new(event_tx_1, rand::random()));

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
