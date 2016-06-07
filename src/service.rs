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

use maidsafe_utilities::thread::RaiiThreadJoiner;
use mio::{self, EventLoop};
use net2;
use socket_addr;
use sodiumoxide;
use sodiumoxide::crypto::box_::{self, PublicKey, SecretKey};
use std::collections::HashMap;
use std::hash::{Hash, Hasher, SipHasher};
use std::io;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use bootstrap::Bootstrap;
use config_handler::{self, Config};
use connect::{ConnectionCandidate, EstablishDirectConnection};
use connection_listener::ConnectionListener;
use core::{Context, Core, CoreMessage};
use error::CrustError;
use event::Event;
use nat::mapped_tcp_socket::MappingTcpSocket;
use nat::mapping_context::MappingContext;
use nat::punch_hole::PunchHole;
use nat::rendezvous_info::{PubRendezvousInfo, PrivRendezvousInfo, gen_rendezvous_info};
use peer_id::{self, PeerId};
use service_discovery::ServiceDiscovery;
use socket::Socket;
use static_contact_info::StaticContactInfo;

#[derive(Debug, Clone, Copy)]
pub struct ConnectionId {
    pub active_connection: Option<Context>,
    pub currently_handshaking: usize,
}

pub type ConnectionMap = Arc<Mutex<HashMap<PeerId, ConnectionId>>>;

const BOOTSTRAP_CONTEXT: Context = Context(0);
const SERVICE_DISCOVERY_CONTEXT: Context = Context(1);

const SERVICE_DISCOVERY_DEFAULT_PORT: u16 = 5483;

/// The result of a `Service::prepare_contact_info` call.
#[derive(Debug)]
pub struct ConnectionInfoResult {
    /// The token that was passed to `prepare_connection_info`.
    pub result_token: u32,
    /// The new contact info, if successful.
    pub result: io::Result<PrivConnectionInfo>,
}

/// Contact info generated by a call to `Service::prepare_contact_info`.
#[derive(Debug)]
pub struct PrivConnectionInfo {
    id: PeerId,
    tcp_info: PubRendezvousInfo,
    priv_tcp_info: PrivRendezvousInfo,
    tcp_socket: Option<net2::TcpBuilder>,
    static_contact_info: StaticContactInfo,
}

impl PrivConnectionInfo {
    /// Convert our connection info to theirs so that we can give it to peer.
    pub fn to_pub_connection_info(&self) -> PubConnectionInfo {
        PubConnectionInfo {
            tcp_info: self.tcp_info.clone(),
            static_contact_info: self.static_contact_info.clone(),
            // tcp_addrs: self.tcp_addrs.clone(),
            id: self.id,
        }
    }
}

/// Contact info used to connect to another peer.
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct PubConnectionInfo {
    tcp_info: PubRendezvousInfo,
    static_contact_info: StaticContactInfo,
    id: PeerId,
}

impl PubConnectionInfo {
    /// Returns the `PeerId` of the node that created this connection info.
    pub fn id(&self) -> PeerId {
        self.id
    }
}

/// A structure representing a connection manager.
pub struct Service {
    config: Config,
    cm: ConnectionMap,
    event_tx: ::CrustEventSender,
    is_listenner_running: bool,
    is_service_discovery_running: bool,
    mapping_context: Arc<MappingContext>,
    mio_tx: mio::Sender<CoreMessage>,
    name_hash: u64,
    our_keys: (PublicKey, SecretKey),
    our_contact_info: Arc<Mutex<StaticContactInfo>>,
    _thread_joiner: RaiiThreadJoiner,
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

        let mut event_loop = try!(EventLoop::new());
        let mio_tx = event_loop.channel();
        let our_keys = box_::gen_keypair();
        let our_id = peer_id::new(our_keys.0);
        let name_hash = name_hash(&config.network_name);

        // Form our initial contact info
        let our_contact_info = Arc::new(Mutex::new(StaticContactInfo::default()));
        let mapping_context = MappingContext::new();

        let joiner = RaiiThreadJoiner::new(thread!(format!("Crust {:?} event loop", our_id), move || {
            let mut core = Core::with_context_counter(2);
            event_loop.run(&mut core).expect("EventLoop failed to run");
        }));

        Ok(Service {
            cm: Arc::new(Mutex::new(HashMap::new())),
            config: config,
            event_tx: event_tx,
            is_listenner_running: false,
            is_service_discovery_running: false,
            mapping_context: Arc::new(mapping_context),
            mio_tx: mio_tx,
            name_hash: name_hash,
            our_keys: our_keys,
            our_contact_info: our_contact_info,
            _thread_joiner: joiner,
        })
    }

    /// Starts listening for beacon broadcasts.
    pub fn start_service_discovery(&mut self) {
        if self.is_service_discovery_running {
            return;
        } else {
            self.is_service_discovery_running = true;
        }

        let our_contact_info = self.our_contact_info.clone();
        let port = self.config
            .service_discovery_port
            .unwrap_or(SERVICE_DISCOVERY_DEFAULT_PORT);

        let _ = self.post(move |core, event_loop| {
            if let Err(e) = ServiceDiscovery::start(core,
                                                    event_loop,
                                                    our_contact_info,
                                                    SERVICE_DISCOVERY_CONTEXT,
                                                    port) {
                error!("Could not start ServiceDiscovery: {:?}", e);
            }
        });
    }

    /// Enable listening and responding to peers searching for us. This will allow others finding us
    /// by interrogating the network.
    pub fn set_service_discovery_listen(&self, listen: bool) {
        if self.is_service_discovery_running {
            let _ = self.post(move |core, _| {
                let state = core.get_state(SERVICE_DISCOVERY_CONTEXT)
                    .expect("ServiceDiscovery not found");
                let mut state = state.borrow_mut();

                let service_discovery = match state.as_any().downcast_mut::<ServiceDiscovery>() {
                    Some(b) => b,
                    None => panic!("&ServiceDiscovery isn't a ServiceDiscovery!"),
                };

                service_discovery.set_listen(listen);
            });
        }
    }

    /// Start the bootstrapping procedure.
    // TODO: accept a blacklist parameter.
    pub fn start_bootstrap(&mut self) -> ::Res<()> {
        let config = self.config.clone();
        let our_public_key = self.our_keys.0;
        let name_hash = self.name_hash;
        let cm = self.cm.clone();
        let event_tx = self.event_tx.clone();

        self.post(move |core, event_loop| {
            if let Err(e) = Bootstrap::start(core,
                                             event_loop,
                                             name_hash,
                                             our_public_key,
                                             cm,
                                             &config,
                                             BOOTSTRAP_CONTEXT,
                                             SERVICE_DISCOVERY_CONTEXT,
                                             event_tx.clone()) {
                error!("Could not bootstrap: {:?}", e);
                let _ = event_tx.send(Event::BootstrapFailed);
            }
        })
    }

    /// Stop the bootstraping procedure
    pub fn stop_bootstrap(&mut self) -> ::Res<()> {
        self.post(move |mut core, mut event_loop| {
            core.terminate_state(event_loop, BOOTSTRAP_CONTEXT);
        })
    }

    /// Starts accepting TCP connections.
    pub fn start_listening_tcp(&mut self) -> ::Res<()> {
        // Do not create more than one listener.
        if self.is_listenner_running {
            return Ok(());
        } else {
            self.is_listenner_running = true;
        }

        let cm = self.cm.clone();
        let mapping_context = self.mapping_context.clone();
        let port = self.config.tcp_acceptor_port.unwrap_or(0);
        let our_public_key = self.our_keys.0;
        let name_hash = self.name_hash;
        let our_contact_info = self.our_contact_info.clone();
        let event_tx = self.event_tx.clone();

        self.post(move |core, event_loop| {
            ConnectionListener::start(core,
                                      event_loop,
                                      None,
                                      port,
                                      our_public_key,
                                      name_hash,
                                      cm,
                                      mapping_context,
                                      our_contact_info,
                                      event_tx);
        })
    }

    /// connect to peer
    pub fn connect(&self,
                   our_connection_info: PrivConnectionInfo,
                   their_connection_info: PubConnectionInfo)
                   -> ::Res<()> {
        let event_tx = self.event_tx.clone();
        let cm = self.cm.clone();
        let our_public_key = self.our_keys.0;
        let our_id = peer_id::new(our_public_key);
        let name_hash = self.name_hash;

        // FIXME: check this error
        let _ = self.post(move |core, event_loop| {
            let their_id = their_connection_info.id.clone();

            if cm.lock().unwrap().contains_key(&their_id) {
                warn!("Already connected to {:?}", their_id);
                return;
            }

            let their_acceptors = their_connection_info.static_contact_info.tcp_acceptors.clone();
            let acceptor_count = their_acceptors.len();
            for (i, socket_addr::SocketAddr(addr)) in their_acceptors.into_iter().enumerate() {
                let cm0 = cm.clone();
                let cm1 = cm.clone();
                let event_tx_clone = event_tx.clone();

                {
                    let mut guard = cm.lock().unwrap();
                    guard.entry(their_id)
                        .or_insert(ConnectionId {
                            active_connection: None,
                            currently_handshaking: 0,
                        })
                        .currently_handshaking += 1;
                }

                EstablishDirectConnection::start(core,
                                                 event_loop,
                                                 addr,
                                                 our_public_key,
                                                 name_hash,
                                                 move |core, event_loop, res| {
                    match res {
                        Ok((token, socket)) => {
                            ConnectionCandidate::start(core,
                                                       event_loop,
                                                       token,
                                                       socket,
                                                       cm0,
                                                       our_id,
                                                       their_id,
                                                       event_tx_clone);
                        }
                        Err(e) => {
                            {
                                let mut guard = cm1.lock().unwrap();
                                let remove = {
                                    let conn_id = guard.get_mut(&their_id).expect("Logic Error");
                                    conn_id.currently_handshaking -= 1;
                                    conn_id.currently_handshaking == 0 &&
                                    conn_id.active_connection.is_none()
                                };
                                if !remove {
                                    // There is an active OR atleast 1 currently handshaking
                                    // connection
                                    return;
                                }
                                let _ = guard.remove(&their_id);
                            }

                            if i < acceptor_count - 1 {
                                return;
                            }
                            let _ = event_tx_clone.send(Event::NewPeer(Err(e), their_id));
                        }
                    }
                });
            }

            if let Some(tcp_socket) = our_connection_info.tcp_socket {
                {
                    let mut guard = cm.lock().unwrap();
                    guard.entry(their_id)
                        .or_insert(ConnectionId {
                            active_connection: None,
                            currently_handshaking: 0,
                        })
                        .currently_handshaking += 1;
                }
                let event_tx_rc = Rc::new(event_tx);
                let connection_map_cloned = cm.clone();
                let event_tx_rc_cloned = event_tx_rc.clone();
                let res = PunchHole::start(core,
                                         event_loop,
                                         tcp_socket,
                                         our_connection_info.priv_tcp_info,
                                         their_connection_info.tcp_info,
                                         move |core, event_loop, stream_opt|
                {
                    match stream_opt {
                        Some((stream, token)) => {
                            let socket = Socket::wrap(stream);
                            let event_tx = (&*event_tx_rc_cloned).clone();

                            ConnectionCandidate::start(core,
                                                       event_loop,
                                                       token,
                                                       socket,
                                                       connection_map_cloned,
                                                       our_id,
                                                       their_id,
                                                       event_tx);
                        }
                        None => {
                            {
                                let mut guard = connection_map_cloned.lock().unwrap();
                                let remove = {
                                    let conn_id = guard.get_mut(&their_id).expect("Logic Error");
                                    conn_id.currently_handshaking -= 1;
                                    conn_id.currently_handshaking == 0 &&
                                    conn_id.active_connection.is_none()
                                };
                                if !remove {
                                    // There is an active OR atleast 1 currently handshaking
                                    // connection
                                    return;
                                }
                                let _ = guard.remove(&their_id);
                            }
                            let error = io::Error::new(io::ErrorKind::Other,
                                                       format!("Failed punching hole to peer: {:?}", their_id));
                            let _ = event_tx_rc_cloned.send(Event::NewPeer(Err(error), their_id));
                        }
                    }
                });

                if let Err(e) = res {
                    {
                        let mut guard = cm.lock().unwrap();
                        let remove = {
                            let conn_id = guard.get_mut(&their_id).expect("Logic Error");
                            conn_id.currently_handshaking -= 1;
                            conn_id.currently_handshaking == 0 &&
                            conn_id.active_connection.is_none()
                        };
                        if !remove {
                            // There is an active OR at least 1 currently handshaking connection
                            return;
                        }
                        let _ = guard.remove(&their_id);
                    }

                    if let Ok(event_tx) = Rc::try_unwrap(event_tx_rc) {
                        let msg = format!("Io error starting hole-punching: {}", e);
                        let error = io::Error::new(io::ErrorKind::Other, msg);
                        let _ = event_tx.send(Event::NewPeer(Err(error), their_id));
                    }
                }
            }
        });

        Ok(())
    }

    /// Disconnect from the given peer and returns whether there was a connection at all.
    pub fn disconnect(&self, peer_id: PeerId) -> bool {
        let context = match self.cm.lock().unwrap().get(&peer_id) {
            Some(&ConnectionId { active_connection: Some(context), .. }) => context,
            _ => return false,
        };

        let _ = self.post(move |mut core, mut event_loop| {
            if let Some(state) = core.get_state(context) {
                state.borrow_mut().terminate(&mut core, &mut event_loop);
            }
        });

        true
    }

    /// sending data to a peer(according to it's u64 peer_id)
    pub fn send(&self, peer_id: PeerId, data: Vec<u8>, _priority: u8) -> ::Res<()> {
        // TODO(Spandan) This is wrong. Correct size can only be obtained post serialisation of
        // enum in which this will be put
        if data.len() > ::MAX_PAYLOAD_SIZE {
            return Err(CrustError::PayloadSizeProhibitive);
        }

        let context = match self.cm.lock().unwrap().get(&peer_id) {
            Some(&ConnectionId { active_connection: Some(context), .. }) => context,
            _ => return Err(CrustError::PeerNotFound(peer_id)),
        };

        self.post(move |mut core, mut event_loop| {
            if let Some(state) = core.get_state(context) {
                state.borrow_mut().write(&mut core, &mut event_loop, data);
            }
        })
    }

    /// Lookup a mapped udp socket based on result_token
    // TODO: immediate return in case of sender.send() returned with NotificationError
    pub fn prepare_connection_info(&self, result_token: u32) {
        let event_tx = self.event_tx.clone();
        let our_pub_key = self.our_keys.0;
        let static_contact_info = self.our_contact_info.lock().unwrap().clone();
        let mapping_context = self.mapping_context.clone();
        if let Err(e) = self.post(move |mut core, mut event_loop| {
            let event_tx_clone = event_tx.clone();
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
            match MappingTcpSocket::new(core,
                                        event_loop,
                                        &addr,
                                        &mapping_context,
                                        move |_, _, socket, addrs| {
                let event_tx = event_tx_clone;
                let (our_priv_tcp_info, our_pub_tcp_info) = gen_rendezvous_info(addrs);
                let event = Event::ConnectionInfoPrepared(ConnectionInfoResult {
                    result_token: result_token,
                    result: Ok(PrivConnectionInfo {
                        id: peer_id::new(our_pub_key),
                        tcp_info: our_pub_tcp_info,
                        priv_tcp_info: our_priv_tcp_info,
                        tcp_socket: Some(socket),
                        static_contact_info: static_contact_info,
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
                result: Err(io::Error::new(io::ErrorKind::Other,
                                           format!("Failed to register task with mio \
                                                    eventloop: {}",
                                                   e))),
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
        peer_id::new(self.our_keys.0)
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
    use std::collections::{hash_map, HashMap};
    use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};
    use std::sync::{mpsc, Arc, Barrier};
    // use maidsafe_utilities::log;
    use std::sync::mpsc::Receiver;
    use std::thread::JoinHandle;
    use std::time::Duration;
    use maidsafe_utilities;

    use event::Event;
    use tests::{get_event_sender, timebomb};

    #[test]
    fn direct_connect_two_peers() {
        timebomb(Duration::from_secs(5), || {
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
    fn rendezvous_connect_two_peers() {
        maidsafe_utilities::log::init(true).unwrap();
        timebomb(Duration::from_secs(10), || {
            let (event_tx_0, event_rx_0) = get_event_sender();
            let service_0 = unwrap_result!(Service::new(event_tx_0));

            let (event_tx_1, event_rx_1) = get_event_sender();
            let service_1 = unwrap_result!(Service::new(event_tx_1));

            connect(&service_0, &event_rx_0, &service_1, &event_rx_1);
            debug!("Exchanging messages ...");
            exchange_messages(&service_0, &event_rx_0, &service_1, &event_rx_1);
        });
        ::std::thread::sleep(Duration::from_secs(1));
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

        debug!("Connecting ...");
        unwrap_result!(service_0.connect(priv_info_0, pub_info_1));
        if cfg!(windows) {
            ::std::thread::sleep(Duration::from_millis(100));
        }
        unwrap_result!(service_1.connect(priv_info_1, pub_info_0));

        debug!("Receiving NewPeers ...");
        expect_event!(event_rx_0, Event::NewPeer(res, id) => {
            unwrap_result!(res);
            assert_eq!(id, service_1.id());
        });

        expect_event!(event_rx_1, Event::NewPeer(res, id) => {
            unwrap_result!(res);
            assert_eq!(id, service_0.id());
        });

        debug!("Finished connecting");
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
        const NUM_SERVICES: usize = 15;
        const MSG_SIZE: usize = 1024;
        const NUM_MSGS: usize = 257;

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
                let config = unwrap_result!(::config_handler::read_config_file());
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
                            Event::NewPeer(Ok(()), their_id) => their_id,
                            m => panic!("Expected NewPeer message. Got message {:?}", m),
                        };
                        match their_ids.insert(their_id, 0u32) {
                            Some(_) => panic!("Received two NewPeer events for same peer!"),
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
