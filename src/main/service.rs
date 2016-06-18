// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher, SipHasher};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use common::{self, Core, CoreMessage, Priority};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use mio::{self, EventLoop, Token};
use nat::{MappedTcpSocket, MappingContext};
use service_discovery::ServiceDiscovery;
use sodiumoxide;
use sodiumoxide::crypto::box_::{self, PublicKey, SecretKey};
use main::config_handler::{self, Config};
use main::{Bootstrap, Connect, ConnectionId, ConnectionInfoResult, ConnectionListener,
           ConnectionMap, CrustError, Event, PeerId, PrivConnectionInfo, PubConnectionInfo};

const BOOTSTRAP_TOKEN: Token = Token(0);
const SERVICE_DISCOVERY_TOKEN: Token = Token(1);
const LISTENER_TOKEN: Token = Token(2);

const SERVICE_DISCOVERY_DEFAULT_PORT: u16 = 5484;
/// A structure representing a connection manager.
pub struct Service {
    config: Config,
    cm: ConnectionMap,
    event_tx: ::CrustEventSender,
    mc: Arc<MappingContext>,
    mio_tx: mio::Sender<CoreMessage>,
    name_hash: u64,
    our_keys: (PublicKey, SecretKey),
    our_listeners: Arc<Mutex<Vec<SocketAddr>>>,
    _raii_joiner: RaiiThreadJoiner,
}

impl Service {
    /// Constructs a service.
    pub fn new(event_tx: ::CrustEventSender) -> ::Res<Self> {
        Service::with_config(event_tx, try!(config_handler::read_config_file()))
    }

    /// Constructs a service with the given config. User needs to create an asynchronous channel,
    /// and provide the sender half to this method. Receiver will receive all `Event`s from this
    /// library.
    pub fn with_config(event_tx: ::CrustEventSender, config: Config) -> ::Res<Service> {
        sodiumoxide::init();

        let mut el = try!(EventLoop::new());
        let mio_tx = el.channel();
        let our_keys = box_::gen_keypair();
        let our_id = PeerId(our_keys.0);
        let name_hash = name_hash(&config.network_name);

        // Form our initial contact info
        let our_listeners = Arc::new(Mutex::new(Vec::with_capacity(5)));
        let mut mc = try!(MappingContext::new());
        mc.add_peer_listeners_no_check(config.hard_coded_contacts
            .iter()
            .map(|elt| elt.0)
            .collect());

        let joiner =
            RaiiThreadJoiner::new(thread!(format!("Crust {:?} event loop", our_id), move || {
                let mut core = Core::with_token_counter(3);
                el.run(&mut core).expect("EventLoop failed to run");
            }));

        Ok(Service {
            cm: Arc::new(Mutex::new(HashMap::new())),
            config: config,
            event_tx: event_tx,
            mc: Arc::new(mc),
            mio_tx: mio_tx,
            name_hash: name_hash,
            our_keys: our_keys,
            our_listeners: our_listeners,
            _raii_joiner: joiner,
        })
    }

    /// Starts listening for beacon broadcasts.
    pub fn start_service_discovery(&mut self) {
        let our_listeners = self.our_listeners.clone();
        let port = self.config.service_discovery_port.unwrap_or(SERVICE_DISCOVERY_DEFAULT_PORT);

        let _ = self.post(move |core, el| {
            if core.get_state(SERVICE_DISCOVERY_TOKEN).is_none() {
                if let Err(e) = ServiceDiscovery::start(core,
                                                        el,
                                                        our_listeners,
                                                        SERVICE_DISCOVERY_TOKEN,
                                                        port) {
                    warn!("Could not start ServiceDiscovery: {:?}", e);
                }
            }
        });
    }

    /// Enable listening and responding to peers searching for us. This will allow others finding us
    /// by interrogating the network.
    pub fn set_service_discovery_listen(&self, listen: bool) {
        let _ = self.post(move |core, _| {
            let state = match core.get_state(SERVICE_DISCOVERY_TOKEN) {
                Some(state) => state,
                None => return,
            };
            let mut state = state.borrow_mut();
            let service_discovery = match state.as_any().downcast_mut::<ServiceDiscovery>() {
                Some(sd) => sd,
                None => {
                    warn!("Token reserved for ServiceDiscovery has something else.");
                    return;
                }
            };
            service_discovery.set_listen(listen);
        });
    }

    /// Start the bootstrapping procedure. It will auto terminate after indicating success or
    /// failure
    pub fn start_bootstrap(&mut self, blacklist: HashSet<SocketAddr>) -> ::Res<()> {
        let config = self.config.clone();
        let our_pk = self.our_keys.0;
        let name_hash = self.name_hash;
        let cm = self.cm.clone();
        let event_tx = self.event_tx.clone();

        self.post(move |core, el| {
            if core.get_state(BOOTSTRAP_TOKEN).is_none() {
                if let Err(e) = Bootstrap::start(core,
                                                 el,
                                                 name_hash,
                                                 our_pk,
                                                 cm,
                                                 &config,
                                                 blacklist,
                                                 BOOTSTRAP_TOKEN,
                                                 SERVICE_DISCOVERY_TOKEN,
                                                 event_tx.clone()) {
                    error!("Could not bootstrap: {:?}", e);
                    let _ = event_tx.send(Event::BootstrapFailed);
                }
            }
        })
    }

    /// Stop the bootstraping procedure explicitly
    pub fn stop_bootstrap(&mut self) -> ::Res<()> {
        self.post(move |mut core, mut el| {
            if let Some(state) = core.get_state(BOOTSTRAP_TOKEN) {
                state.borrow_mut().terminate(core, el);
            }
        })
    }

    /// Starts accepting TCP connections. This is persistant until it errors out or is stopped
    /// explicitly.
    pub fn start_listening_tcp(&mut self) -> ::Res<()> {
        let cm = self.cm.clone();
        let mc = self.mc.clone();
        let port = self.config.tcp_acceptor_port.unwrap_or(0);
        let our_pk = self.our_keys.0;
        let name_hash = self.name_hash;
        let our_listeners = self.our_listeners.clone();
        let event_tx = self.event_tx.clone();

        self.post(move |core, el| {
            if core.get_state(LISTENER_TOKEN).is_none() {
                ConnectionListener::start(core,
                                          el,
                                          None,
                                          port,
                                          our_pk,
                                          name_hash,
                                          cm,
                                          mc,
                                          our_listeners,
                                          LISTENER_TOKEN,
                                          event_tx);
            }
        })
    }

    /// Stops Listener explicitly and stops accepting TCP connections.
    pub fn stop_tcp_listener(&mut self) -> ::Res<()> {
        self.post(move |core, el| {
            if let Some(state) = core.get_state(LISTENER_TOKEN) {
                state.borrow_mut().terminate(core, el);
            }
        })
    }

    /// Connect to peer
    pub fn connect(&self, our_ci: PrivConnectionInfo, their_ci: PubConnectionInfo) -> ::Res<()> {
        if self.cm.lock().unwrap().contains_key(&their_ci.id) {
            warn!("Already connected OR already in process of connecting to {:?}",
                  their_ci.id);
            return Ok(());
        }

        let event_tx = self.event_tx.clone();
        let cm = self.cm.clone();
        let our_nh = self.name_hash;

        Ok(try!(self.post(move |core, el| {
            let _ = Connect::start(core, el, our_ci, their_ci, cm, our_nh, event_tx);
        })))
    }

    /// Disconnect from the given peer and returns whether there was a connection at all.
    pub fn disconnect(&self, peer_id: PeerId) -> bool {
        let token = match self.cm.lock().unwrap().get(&peer_id) {
            Some(&ConnectionId { active_connection: Some(token), .. }) => token,
            _ => return false,
        };

        let _ = self.post(move |mut core, mut el| {
            if let Some(state) = core.get_state(token) {
                state.borrow_mut().terminate(&mut core, &mut el);
            }
        });

        true
    }

    /// sending data to a peer(according to it's u64 peer_id)
    pub fn send(&self, peer_id: PeerId, msg: Vec<u8>, priority: Priority) -> ::Res<()> {
        let token = match self.cm.lock().unwrap().get(&peer_id) {
            Some(&ConnectionId { active_connection: Some(token), .. }) => token,
            _ => return Err(CrustError::PeerNotFound(peer_id)),
        };

        self.post(move |mut core, mut el| {
            if let Some(state) = core.get_state(token) {
                state.borrow_mut().write(&mut core, &mut el, msg, priority);
            }
        })
    }

    /// Lookup a mapped udp socket based on result_token
    // TODO: immediate return in case of sender.send() returned with NotificationError
    pub fn prepare_connection_info(&self, result_token: u32) {
        let event_tx = self.event_tx.clone();
        let our_pub_key = self.our_keys.0;
        let our_listeners =
            self.our_listeners.lock().unwrap().iter().map(|e| common::SocketAddr(*e)).collect();
        let mc = self.mc.clone();
        if let Err(e) = self.post(move |mut core, mut el| {
            let event_tx_clone = event_tx.clone();
            match MappedTcpSocket::start(core, el, 0, &mc, move |_, _, socket, addrs| {
                let hole_punch_addrs =
                    addrs.into_iter().filter(|elt| elt.global()).map(|elt| elt.addr).collect();
                let event_tx = event_tx_clone;
                let event = Event::ConnectionInfoPrepared(ConnectionInfoResult {
                    result_token: result_token,
                    result: Ok(PrivConnectionInfo {
                        id: PeerId(our_pub_key),
                        for_direct: our_listeners,
                        for_hole_punch: hole_punch_addrs,
                        hole_punch_socket: socket,
                    }),
                });
                let _ = event_tx.send(event);
            }) {
                Ok(()) => (),
                Err(e) => {
                    debug!("Error mapping tcp socket: {}", e);
                    let _ = event_tx.send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                        result_token: result_token,
                        result: Err(From::from(e)),
                    }));
                }
            };
        }) {
            let _ = self.event_tx.send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                result_token: result_token,
                result: Err(From::from(e)),
            }));
        }
    }

    /// Check if we are connected to the given peer
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        match self.cm.lock().unwrap().get(peer_id) {
            Some(&ConnectionId { active_connection: Some(_), .. }) => true,
            _ => false,
        }
    }

    /// Returns our ID.
    pub fn id(&self) -> PeerId {
        PeerId(self.our_keys.0)
    }

    fn post<F>(&self, f: F) -> ::Res<()>
        where F: FnOnce(&mut Core, &mut EventLoop<Core>) + Send + 'static
    {
        Ok(try!(self.mio_tx.send(CoreMessage::new(f))))
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.post(|_, el| el.shutdown());
    }
}

/// Returns a hash of the network name.
fn name_hash(network_name: &Option<String>) -> u64 {
    let mut hasher = SipHasher::new();
    debug!("Network name: {:?}", network_name);
    network_name.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{HashMap, hash_map};
    use std::sync::atomic::{ATOMIC_USIZE_INIT, AtomicUsize, Ordering};
    use std::sync::mpsc::Receiver;
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use maidsafe_utilities;
    use main::{Event, PrivConnectionInfo, PubConnectionInfo};
    use tests::{get_event_sender, timebomb};

    #[test]
    fn direct_connect_two_peers() {
        timebomb(Duration::from_secs(30), || {
            let (event_tx_0, event_rx_0) = get_event_sender();
            let mut service_0 = unwrap_result!(Service::new(event_tx_0));

            unwrap_result!(service_0.start_listening_tcp());
            expect_event!(event_rx_0, Event::ListenerStarted(_));

            let (event_tx_1, event_rx_1) = get_event_sender();
            let mut service_1 = unwrap_result!(Service::new(event_tx_1));

            unwrap_result!(service_1.start_listening_tcp());
            expect_event!(event_rx_1, Event::ListenerStarted(_));

            connect(&service_0, &event_rx_0, &service_1, &event_rx_1);
            exchange_messages(&service_0, &event_rx_0, &service_1, &event_rx_1);
        })
    }

    #[test]
    #[ignore]
    fn rendezvous_connect_two_peers() {
        maidsafe_utilities::log::init(true).unwrap();
        timebomb(Duration::from_secs(30), || {
            let (event_tx_0, event_rx_0) = get_event_sender();
            let service_0 = unwrap_result!(Service::new(event_tx_0));

            let (event_tx_1, event_rx_1) = get_event_sender();
            let service_1 = unwrap_result!(Service::new(event_tx_1));

            connect(&service_0, &event_rx_0, &service_1, &event_rx_1);
            debug!("Exchanging messages ...");
            exchange_messages(&service_0, &event_rx_0, &service_1, &event_rx_1);
        });
        thread::sleep(Duration::from_secs(1));
    }

    fn connect(service_0: &Service,
               event_rx_0: &Receiver<Event>,
               service_1: &Service,
               event_rx_1: &Receiver<Event>) {
        service_0.prepare_connection_info(0);
        service_1.prepare_connection_info(0);

        let conn_info_result_0 =
            expect_event!(event_rx_0, Event::ConnectionInfoPrepared(result) => result);
        let conn_info_result_1 =
            expect_event!(event_rx_1, Event::ConnectionInfoPrepared(result) => result);

        let priv_info_0 = unwrap_result!(conn_info_result_0.result);
        let priv_info_1 = unwrap_result!(conn_info_result_1.result);
        let pub_info_0 = priv_info_0.to_pub_connection_info();
        let pub_info_1 = priv_info_1.to_pub_connection_info();

        unwrap_result!(service_0.connect(priv_info_0, pub_info_1));
        if cfg!(windows) {
            thread::sleep(Duration::from_millis(100));
        }
        unwrap_result!(service_1.connect(priv_info_1, pub_info_0));

        expect_event!(event_rx_0, Event::ConnectSuccess(id) => assert_eq!(id, service_1.id()));
        expect_event!(event_rx_1, Event::ConnectSuccess(id) => assert_eq!(id, service_0.id()));
    }

    fn exchange_messages(service_0: &Service,
                         event_rx_0: &Receiver<Event>,
                         service_1: &Service,
                         event_rx_1: &Receiver<Event>) {
        use rand;
        use std::iter;

        let id_0 = service_0.id();
        let id_1 = service_1.id();

        let data_0: Vec<u8> = iter::repeat(()).take(32).map(|()| rand::random()).collect();
        let send_0 = data_0.clone();
        let data_1: Vec<u8> = iter::repeat(()).take(32).map(|()| rand::random()).collect();
        let send_1 = data_1.clone();

        unwrap_result!(service_0.send(id_1, data_0, 0));
        unwrap_result!(service_1.send(id_0, data_1, 0));

        let recv_1 = expect_event!(event_rx_0, Event::NewMessage(id, recv) => {
            assert_eq!(id, id_1);
            recv
        });

        let recv_0 = expect_event!(event_rx_1, Event::NewMessage(id, recv) => {
            assert_eq!(id, id_0);
            recv
        });

        assert_eq!(recv_0, send_0);
        assert_eq!(recv_1, send_1);
    }

    fn prepare_connection_info(service: &mut Service,
                               event_rx: &Receiver<Event>)
                               -> PrivConnectionInfo {
        static TOKEN_COUNTER: AtomicUsize = ATOMIC_USIZE_INIT;
        let token = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed) as u32;

        service.prepare_connection_info(token);

        match unwrap_result!(event_rx.recv()) {
            Event::ConnectionInfoPrepared(cir) => {
                assert_eq!(cir.result_token, token);
                unwrap_result!(cir.result)
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
            event_rx: Receiver<Event>,
            service: Service,
            connection_id_rx: Receiver<PubConnectionInfo>,
            our_cis: Vec<PrivConnectionInfo>,
            our_index: usize,
        }

        impl TestNode {
            fn new(index: usize) -> (TestNode, mpsc::Sender<PubConnectionInfo>) {
                let (event_sender, event_rx) = get_event_sender();
                let config = unwrap_result!(::main::config_handler::read_config_file());
                let mut service = unwrap_result!(Service::with_config(event_sender, config));
                // Start listener so that the test works without hole punching.
                assert!(service.start_listening_tcp().is_ok());
                match unwrap_result!(event_rx.recv()) {
                    Event::ListenerStarted(_) => (),
                    m => panic!("Unexpected event: {:?}", m),
                }
                let (ci_tx, ci_rx) = mpsc::channel();
                (TestNode {
                    event_rx: event_rx,
                    service: service,
                    connection_id_rx: ci_rx,
                    our_cis: Vec::new(),
                    our_index: index,
                },
                 ci_tx)
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

            fn run(self, send_barrier: Arc<Barrier>, drop_barrier: Arc<Barrier>) -> JoinHandle<()> {
                thread!("run!", move || {
                    for (our_ci, their_ci) in self.our_cis
                        .into_iter()
                        .zip(self.connection_id_rx.into_iter()) {
                        let _ = self.service.connect(our_ci, their_ci);
                    }
                    let mut their_ids = HashMap::new();
                    for _ in 0..NUM_SERVICES - 1 {
                        let their_id = match unwrap_result!(self.event_rx.recv()) {
                            Event::ConnectSuccess(their_id) => their_id,
                            m => panic!("Expected ConnectSuccess message. Got message {:?}", m),
                        };
                        match their_ids.insert(their_id, 0u32) {
                            Some(_) => panic!("Received two ConnectSuccess events for same peer!"),
                            None => (),
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
                            let _ = self.service.send(*their_id, msg, 0);
                        }
                    }

                    for _ in 0..((NUM_SERVICES - 1) * NUM_MSGS) {
                        match unwrap_result!(self.event_rx.recv()) {
                            Event::NewMessage(their_id, msg) => {
                                let n = msg[0];
                                assert_eq!(msg.len(), MSG_SIZE);
                                for m in msg {
                                    assert_eq!(n, m);
                                }
                                match their_ids.entry(their_id.clone()) {
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
                        Ok(m) => {
                            match m {
                                Event::LostPeer(..) => (),
                                _ => panic!("Unexpected message when shutting down: {:?}", m),
                            }
                        }
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
        let timeout_ms = 10000 * (NUM_MSGS * (NUM_SERVICES * (NUM_SERVICES - 1)) / 2) as u64;
        timebomb(Duration::from_millis(timeout_ms), move || {
            for thread in threads {
                unwrap_result!(thread.join());
            }
        });
    }
}
