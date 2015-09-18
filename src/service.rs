// Copyright 2015 MaidSafe.net limited.
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

use std::io;
use std::sync::mpsc::Sender;
use std::thread;
use std::boxed::FnBox;
use std::thread::JoinHandle;
use std::sync::{Arc, Mutex};

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use beacon;
use bootstrap_handler::BootstrapHandler;
use config_handler::{Config, read_config_file};
use getifaddrs::{getifaddrs, filter_loopback};
use transport;
use transport::{Endpoint, Port, Message};
use ip;
use map_external_port::async_map_external_port;
use connection::Connection;

use state::State;
use event::Event;

/// Type used to represent serialised data in a message.
pub type Bytes = Vec<u8>;
type Closure = Box<FnBox(&mut State) + Send>;

/// A structure representing a connection manager.
///
/// This abstraction has a hidden dependency on a config file. Refer to [the docs for `FileHandler`]
/// (../file_handler/struct.FileHandler.html) and [an example config file flowchart]
/// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf) for more
/// information.
pub struct Service {
    beacon_guid_and_port : Option<(beacon::GUID, u16)>,
    config               : Config,
    cmd_sender           : Sender<Closure>,
}

impl Service {
    /// Constructs a connection manager. User needs to create an asynchronous channel, and provide
    /// the sender half to this method. Receiver will receive all `Event`s from this library.
    pub fn new(event_sender: Sender<Event>) -> io::Result<Service> {
        let config = read_config_file().unwrap_or_else(|e| {
            debug!("Crust failed to read config file; Error: {:?};", e);
            ::config_handler::create_default_config_file();
            let default = Config::make_default();
            debug!("Using default beacon_port {:?} and default bootstrapping methods enabled",
                default.beacon_port);
            default
        });

        Service::construct(event_sender, config)
    }

    /// Construct a connection manager. As with the `Service::new` function,
    /// but will not implicitly start any network activity. This construtor is intended
    /// only for testing purposes.
    pub fn new_inactive(event_sender: Sender<Event>)
            -> io::Result<Service> {
        Service::construct(event_sender, Config::make_zero())
    }

    fn construct(event_sender: Sender<Event>, config: Config)
            -> io::Result<Service> {
        let mut state = State::new(event_sender);
        let cmd_sender = state.cmd_sender.clone();

        let handle = try!(Self::new_thread("run loop", move || {
                                state.run();
                            }));

        let mut service = Service {
                              beacon_guid_and_port : None,
                              config               : config,
                              cmd_sender           : cmd_sender,
                          };

        let beacon_port = service.config.beacon_port.clone();

        if let Some(port) = beacon_port {
            let _ = service.start_broadcast_acceptor(port);
        }

        Ok(service)
    }

    pub fn start_default_acceptors(&mut self) -> Vec<io::Result<Endpoint>> {
        let tcp_listening_port = self.config.tcp_listening_port.clone();
        let utp_listening_port = self.config.utp_listening_port.clone();

        let mut result = Vec::new();

        if let Some(port) = tcp_listening_port {
            result.push(self.start_accepting(Port::Tcp(port)));
        }

        if let Some(port) = utp_listening_port {
            result.push(self.start_accepting(Port::Utp(port)));
        }

        result
    }

    /// Starts listening on all supported protocols. Ports in _hint_ are tried
    /// first.  On failure to listen on none of _hint_ an OS randomly chosen
    /// port will be used for each supported protocol. The actual port used will
    /// be returned on which it started listening for each protocol.
    pub fn start_accepting(&mut self, port: Port) -> io::Result<Endpoint> {
        let acceptor = try!(transport::new_acceptor(port));
        let accept_port = acceptor.local_port();

        Self::accept(self.cmd_sender.clone(), acceptor);

        if self.beacon_guid_and_port.is_some() {
            let contacts = filter_loopback(getifaddrs()).into_iter()
                .map(|ip| { Endpoint::new(ip.addr.clone(), accept_port) })
                .collect::<Vec<_>>();

            Self::post(&self.cmd_sender, move |state : &mut State| {
                state.update_bootstrap_contacts(contacts);
            });
        }

        // FIXME: Instead of hardcoded wrapping in loopback V4, the
        // acceptor should tell us what address it is accepting on.
        Ok(::util::loopback_v4(accept_port))
    }

    fn start_broadcast_acceptor(&mut self, beacon_port: u16) -> io::Result<()> {
        let acceptor = try!(beacon::BroadcastAcceptor::new(beacon_port));

        // Right now we expect this function to succeed only once.
        assert!(self.beacon_guid_and_port.is_none());
        self.beacon_guid_and_port = Some((acceptor.beacon_guid(), acceptor.beacon_port()));

        let sender = self.cmd_sender.clone();

        Self::post(&self.cmd_sender, move |state : &mut State| {
            assert!(state.bootstrap_handler.is_none());
            state.bootstrap_handler = Some(BootstrapHandler::new());

            let thread_result = Self::new_thread("beacon acceptor", move || {
                while let Ok(transport) = acceptor.accept() {
                    let _ = sender.send(Box::new(move |state : &mut State| {
                        state.respond_to_broadcast(transport);
                    }));
                }
            });

            // TODO: Handle gracefuly.
            assert!(thread_result.is_ok());
        });

        Ok(())
    }

    /// This method tries to connect (bootstrap to existing network) to the default or provided
    /// override list of bootstrap nodes (via config file named <current executable>.config).
    ///
    /// If `override_default_bootstrap_methods` is not set in the config file, it will attempt to read
    /// a local cached file named <current executable>.bootstrap.cache to populate the list endpoints
    /// to use for bootstrapping. It will also try `hard_coded_contacts` from config file.
    /// In addition, it will try to use the beacon port (provided via config file) to connect to a peer
    /// on the same LAN.
    /// For more details on bootstrap cache file refer
    /// https://github.com/maidsafe/crust/blob/master/docs/bootstrap.md
    ///
    /// If `override_default_bootstrap_methods` is set in config file, it will only try to connect to
    /// the endpoints in the override list (`hard_coded_contacts`).

    /// All connections (if any) will be dropped before bootstrap attempt is made.
    /// This method returns immediately after dropping any active connections.endpoints
    /// New bootstrap connections will be notified by `NewBootstrapConnection` event.
    /// Its upper layer's responsibility to maintain or drop these connections.
    pub fn bootstrap(&mut self) {
        let config = self.config.clone();
        let beacon_guid_and_port = self.beacon_guid_and_port.clone();

        Self::post(&self.cmd_sender, move |state : &mut State| {
            let contacts = state.populate_bootstrap_contacts(&config, &beacon_guid_and_port);
            state.bootstrap_off_list(contacts.clone(),
                                     beacon_guid_and_port.is_some());
        });
    }

    pub fn stop_bootstrap(&mut self) {
        Self::post(&self.cmd_sender, move |state : &mut State| {
            state.stop_bootstrap();
        });
    }

    /// This should be called before destroying an instance of a Service to allow the
    /// listener threads to join.  Once called, the Service should be destroyed.
    pub fn stop(&mut self) {
        if let Some(beacon_guid_and_port) = self.beacon_guid_and_port {
            beacon::BroadcastAcceptor::stop(&beacon_guid_and_port);
            self.beacon_guid_and_port = None;
        }

        let _ = self.cmd_sender.send(Box::new(move |state: &mut State| {
            state.stop();

            // Connect to our listening ports, this should unblock
            // the threads.
            for port in state.listening_ports.iter() {
                let ip_addr = IpAddr::V4(Ipv4Addr::new(127,0,0,1));
                let _ = transport::connect(Endpoint::new(ip_addr, *port));
            }
        }));
    }

    /// Opens a connection to a remote peer. `endpoints` is a vector of addresses of the remote
    /// peer. All the endpoints will be tried. As soon as a connection is established, it will drop
    /// all other ongoing attempts. On success `Event::NewConnection` with connected `Endpoint` will
    /// be sent to the event channel. On failure, nothing is reported.
    /// Failed attempts are not notified back up to the caller. If the caller wants to know of a
    /// failed attempt, it must maintain a record of the attempt itself which times out if a
    /// corresponding `Event::NewConnection` isn't received.  See also [Process for Connecting]
    /// (https://github.com/maidsafe/crust/blob/master/docs/connect.md) for details on handling of
    /// connect in different protocols.
    pub fn connect(&self, endpoints: Vec<Endpoint>) {
        let is_broadcast_acceptor = self.beacon_guid_and_port.is_some();

        Self::post(&self.cmd_sender, move |state : &mut State| {
            let cmd_sender = state.cmd_sender.clone();

            let _ = Self::new_thread("connect", move || {
                for endpoint in endpoints {
                    if let Ok(transport) = transport::connect(endpoint) {
                        let _ = cmd_sender.send(Box::new(move |state: &mut State| {
                            let _ = state.handle_connect(transport, is_broadcast_acceptor);
                        }));
                    }
                }
            });
        });
    }

    /// Sends a message to specified address (endpoint). Returns Ok(()) if the sending might
    /// succeed, and returns an Err if the address is not connected. Return value of Ok does not
    /// mean that the data will be received. It is possible for the corresponding connection to hang
    /// up immediately after this function returns Ok.
    pub fn send(&self, connection: Connection, message: Bytes) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            let writer_channel = match state.connections.get(&connection) {
                Some(writer_channel) => writer_channel.clone(),
                None => {
                    // TODO: Generate async io::ErrorKind::NotConnected event
                    panic!();
                }
            };

            if let Err(what) = writer_channel.send(Message::UserBlob(message)) {
                // TODO: Generate async error event (BrokenPipe perhaps?).
                panic!();
            }
        })
    }

    /// Closes connection with the specified endpoint.
    pub fn drop_node(&self, connection: Connection) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            let _ = state.connections.remove(&connection);
        })
    }

    /// Returns beacon acceptor port if beacon acceptor is accepting, otherwise returns `None`
    /// (beacon port may be taken by another process). Only useful for tests.
    #[cfg(test)]
    pub fn get_beacon_acceptor_port(&self) -> Option<u16> {
        match self.beacon_guid_and_port {
            Some(beacon_guid_and_port) => Some(beacon_guid_and_port.1),
            None => None,
        }
    }

    fn accept(cmd_sender: Sender<Closure>, acceptor: transport::Acceptor) {
        let cmd_sender2 = cmd_sender.clone();

        Self::post(&cmd_sender, move |state: &mut State| {
            state.listening_ports.insert(acceptor.local_port());

            let _ = Self::new_thread("listen", move || {
                let accept_result = transport::accept(&acceptor);
                let cmd_sender3 = cmd_sender2.clone();

                let _ = cmd_sender2.send(Box::new(move |state: &mut State| {
                    if state.stop_called {
                        return;
                    }

                    match accept_result {
                        Ok(transport) => { let _ = state.handle_accept(transport); },
                        Err(_) => {
                            // TODO: What now? Stop? Start again?
                            panic!();
                        }
                    }

                    Self::accept(cmd_sender3, acceptor);
                }));
            });
        })
    }

    pub fn get_external_endpoints(&self) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            type T = (SocketAddrV4, ip::Endpoint);

            struct Async {
                remaining: usize,
                results: Vec<Endpoint>,
            }

            let internal_eps = state.get_accepting_endpoints();

            let async = Arc::new(Mutex::new(Async {
                remaining: internal_eps.len(),
                results: Vec::new(),
            }));

            for internal_ep in internal_eps {
                let async = async.clone();
                let event_sender = state.event_sender.clone();

                async_map_external_port(&internal_ep.to_ip(),
                                        Box::new(move |results: io::Result<Vec<T>>| {
                    let mut async = async.lock().unwrap();
                    async.remaining -= 1;
                    if let Ok(results) = results {
                        for result in results {
                            let transport_port = match internal_ep {
                                Endpoint::Tcp(_) => Port::Tcp(result.1.port().number()),
                                Endpoint::Utp(_) => Port::Utp(result.1.port().number()),
                            };
                            let ext_ep = Endpoint::new(result.1.ip(), transport_port);
                            async.results.push(ext_ep);
                        }
                    }
                    if async.remaining == 0 {
                        let event = Event::ExternalEndpoints(async.results.clone());
                        let _ = event_sender.send(event);
                    }
                }));
            }
        });
    }

    fn new_thread<F,T>(name: &str, f: F) -> io::Result<JoinHandle<T>> 
            where F: FnOnce() -> T, F: Send + 'static, T: Send + 'static {
        thread::Builder::new().name("Service::".to_string() + name)
                              .spawn(f)
    }

    fn post<F>(sender: &Sender<Closure>, cmd: F) where F: FnBox(&mut State) + Send + 'static {
        assert!(sender.send(Box::new(cmd)).is_ok());
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.stop();
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use connection::Connection;
    use std::thread::spawn;
    use std::thread;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use rustc_serialize::{Decodable, Encodable};
    use cbor::{Decoder, Encoder};
    use transport::{Endpoint, Port};
    use std::sync::{Mutex, Arc};
    use config_handler::write_config_file;
    use std::path::PathBuf;
    use std::fs::remove_file;
    use event::Event;
    use std::io;

    fn encode<T>(value: &T) -> Bytes where T: Encodable
    {
        let mut enc = Encoder::from_memory();
        let _ = enc.encode(&[value]);
        enc.into_bytes()
    }

    fn decode<T>(bytes: &Vec<u8>) -> T where T: Decodable
    {
        let mut dec = Decoder::from_bytes(&bytes[..]);
        dec.decode().next().unwrap().unwrap()
    }

    struct Node {
        service: Service,
        listening_endpoint: Endpoint,
        connections: Arc<Mutex<Vec<Connection>>>
    }

    #[derive(Debug)]
    struct Stats {
        new_connections_count: u32,
        messages_count: u32,
        lost_connection_count: u32
    }

    impl Stats {
        fn new() -> Stats {
            Stats {
                new_connections_count: 0,
                messages_count: 0,
                lost_connection_count: 0,
            }
        }
    }

    impl Node {
        pub fn new(mut cm: Service) -> Node {
            let eps = filter_ok(cm.start_default_acceptors());
            Node {
                service: cm,
                listening_endpoint: eps[0].clone(),
                connections: Arc::new(Mutex::new(Vec::new()))
            }
        }
    }

    fn get_acceptor_endpoint(node: &Arc<Mutex<Node>>) -> Endpoint {
        let node = node.clone();
        let node = node.lock().unwrap();
        node.listening_endpoint.clone()
    }

    fn get_connections(node: &Arc<Mutex<Node>>) -> Vec<Connection> {
        let node = node.clone();
        let node = node.lock().unwrap();
        let eps = node.connections.clone();
        let connections = eps.lock().unwrap();
        connections.clone()
    }

    struct Network {
        nodes: Vec<Arc<Mutex<Node>>>
    }

    impl Network {
        pub fn add(&mut self) -> (Receiver<Event>, Option<u16>, Arc<Mutex<Vec<Connection>>>) {
            let (cm_i, cm_o) = channel();
            let node = Node::new(Service::new(cm_i).unwrap());
            let connections = node.connections.clone();
            let beacon_port = node.service.get_beacon_acceptor_port();
            self.nodes.push(Arc::new(Mutex::new(node)));
            (cm_o, beacon_port, connections)
        }
    }

    struct TestConfigFile {
        pub path: PathBuf
    }

    impl Drop for TestConfigFile {
        fn drop(&mut self) {
            let _ = remove_file(&self.path);
        }
    }

    fn make_temp_config(beacon_port: Option<u16>) -> TestConfigFile {
        let path = write_config_file(Some(5483u16), None, Some(false),
                                     Some(vec![]),
                                     Some(beacon_port.unwrap_or(0u16)))
            .unwrap();
        TestConfigFile{path: path}
    }

    fn filter_ok<T>(vec: Vec<io::Result<T>>) -> Vec<T> {
        vec.into_iter().filter_map(|a|a.ok()).collect()
    }

    #[test]
    fn bootstrap() {
        let _cleaner = ::file_handler::ScopedUserAppDirRemover;
        let (cm1_i, _) = channel();
        let _config_file = make_temp_config(None);

        let mut cm1 = Service::new(cm1_i).unwrap();
        let cm1_ports = filter_ok(cm1.start_default_acceptors());
        assert_eq!(cm1_ports.len(), 1);

        thread::sleep_ms(1000);
        let _config_file = make_temp_config(cm1.get_beacon_acceptor_port());

        let (cm2_i, cm2_o) = channel();
        let mut cm2 = Service::new(cm2_i).unwrap();

        cm2.bootstrap();

        let timeout = ::time::Duration::seconds(5);
        let start = ::time::now();
        let mut result = Err(::std::sync::mpsc::TryRecvError::Empty);
        while ::time::now() < start + timeout && result.is_err() {
            result = cm2_o.try_recv();
            ::std::thread::sleep_ms(100);
        }
        match result {
            Ok(Event::OnConnect(ep)) => {
                debug!("OnConnect {:?}", ep);
            }
            Ok(Event::OnAccept(ep)) => {
                debug!("OnAccept {:?}", ep);
            }
            _ => { assert!(false, "Failed to receive NewConnection event")}
        }
        cm1.stop();
        cm2.stop();
    }

    #[test]
    fn connection_manager() {
        // Wait 2 seconds until previous bootstrap test ends. If not, that test connects to these endpoints.
        thread::sleep_ms(2000);
        let run_cm = |cm: Service, o: Receiver<Event>| {
            spawn(move || {
                for i in o.iter() {
                    match i {
                        Event::OnConnect(other_ep) => {
                            let _ = cm.send(other_ep.clone(), encode(&"hello world".to_string()));
                        },
                        Event::OnAccept(other_ep) => {
                            let _ = cm.send(other_ep.clone(), encode(&"hello world".to_string()));
                        },
                        Event::NewMessage(_, _) => {
                            break;
                        },
                        Event::LostConnection(_) => {
                        },
                        Event::BootstrapFinished => {}
                        Event::ExternalEndpoints(_) => {}
                    }
                }
                // debug!("done");
            })
        };

        let mut temp_configs = vec![make_temp_config(None)];

        let (cm1_i, cm1_o) = channel();
        let mut cm1 = Service::new(cm1_i).unwrap();
        let cm1_eps = filter_ok(cm1.start_default_acceptors());
        assert!(cm1_eps.len() >= 1);

        temp_configs.push(make_temp_config(cm1.get_beacon_acceptor_port()));

        let (cm2_i, cm2_o) = channel();
        let mut cm2 = Service::new(cm2_i).unwrap();
        let cm2_eps = filter_ok(cm2.start_default_acceptors());
        assert!(cm2_eps.len() >= 1);

        cm2.connect(cm1_eps);
        cm1.connect(cm2_eps);

        let runner1 = run_cm(cm1, cm1_o);
        let runner2 = run_cm(cm2, cm2_o);

        assert!(runner1.join().is_ok());
        assert!(runner2.join().is_ok());
    }

    #[test]
    fn network() {
        const NETWORK_SIZE: u32 = 10;
        const MESSAGE_PER_NODE: u32 = 5;

        enum StatEvent {
            Crust(Event),
            Exit,
        }

        let run_cm = |tx: Sender<StatEvent>, o: Receiver<Event>, conns: Arc<Mutex<Vec<Connection>>>| {
            spawn(move || {
                let count: u32 = 0;
                for event in o.iter() {
                    assert!(tx.send(StatEvent::Crust(event.clone())).is_ok());

                    match event {
                        Event::OnConnect(other) => {
                            let mut conns = conns.lock().unwrap();
                            conns.push(other);
                        },
                        Event::OnAccept(other) => {
                            let mut conns = conns.lock().unwrap();
                            conns.push(other);
                        },
                        Event::NewMessage(from, bytes) => {
                            let msg = decode::<String>(&bytes);
                            //println!("Received {:?} from {:?}", msg, from);
                            if count == MESSAGE_PER_NODE * (NETWORK_SIZE - 1) {
                                break;
                            }
                        },
                        _ => {
                            println!("Received event {:?}", event);
                        }
                    }
                }
            })
        };

        let stats_accumulator = |stats: Arc<Mutex<Stats>>, stats_rx: Receiver<StatEvent>|
            spawn(move || {
                let total_msg_count = NETWORK_SIZE * MESSAGE_PER_NODE * (NETWORK_SIZE - 1);

                for event in stats_rx.iter() {
                    let mut stat = stats.lock().unwrap();
                    match event {
                        StatEvent::Crust(event) => {
                            match event {
                                Event::OnConnect(_) => {
                                    stat.new_connections_count += 1;
                                },
                                Event::OnAccept(_) => {
                                    stat.new_connections_count += 1;
                                },
                                Event::NewMessage(_, _data) => {
                                    stat.messages_count += 1;
                                    if stat.messages_count == total_msg_count {
                                        break;
                                    }
                                },
                                Event::LostConnection(_) => {
                                    stat.lost_connection_count += 1;
                                },
                                Event::BootstrapFinished => {},
                                Event::ExternalEndpoints(_) => {},
                            }
                        },
                        StatEvent::Exit => break,
                    }
                }
            });

        let mut network = Network { nodes: Vec::new() };
        let stats = Arc::new(Mutex::new(Stats::new()));
        let (stats_tx, stats_rx) = channel::<StatEvent>();
        let mut runners = Vec::new();
        let mut beacon_port: Option<u16> = None;

        for index in 0..NETWORK_SIZE {
            let _scoped_config = make_temp_config(beacon_port);

            let (receiver, port, connected_eps) = network.add();

            if index == 0 {
                assert!(port.is_some());
                beacon_port = port;
            }

            let runner = run_cm(stats_tx.clone(), receiver, connected_eps);
            runners.push(runner);
        }

        let run_stats = stats_accumulator(stats.clone(), stats_rx);

        let mut listening_eps = network.nodes.iter()
            .map(|node| get_acceptor_endpoint(node))
            .collect::<::std::collections::LinkedList<_>>();

        for node in network.nodes.iter() {
            assert!(listening_eps.pop_front().is_some());

            for ep in listening_eps.iter() {
                let node = node.clone();
                let ep = ep.clone();
                let _ = spawn(move || {
                    let node = node.lock().unwrap();
                    node.service.connect(vec![ep]);
                });
            }
        }

        for node in network.nodes.iter() {
            let mut cs_size = get_connections(node).len();
            while cs_size < (NETWORK_SIZE - 1) as usize {
                cs_size = get_connections(node).len();
            }
        }

        {
            let mut node_i = 0;
            for node in network.nodes.iter() {
                for connection in get_connections(node).into_iter() {
                    let node = node.lock().unwrap();
                    for i in 0..MESSAGE_PER_NODE {
                        let msg = format!("MESSAGE {} from {}", i, node_i);
                        node.service.send(connection, encode(&msg));
                    }
                }
                node_i += 1;
            }
        }

        thread::sleep_ms(2000);
        let _ = stats_tx.send(StatEvent::Exit);

        let _ = run_stats.join();

        for _ in 0..NETWORK_SIZE {
            let _ = network.nodes.remove(0);
        }

        for runner in runners.pop() {
            let _ = runner.join();
        }

        let stats_copy = stats.clone();
        let stat = stats_copy.lock().unwrap();
        assert_eq!(stat.new_connections_count, NETWORK_SIZE * (NETWORK_SIZE - 1));
        assert_eq!(stat.messages_count,  NETWORK_SIZE * MESSAGE_PER_NODE * (NETWORK_SIZE - 1));
        assert_eq!(stat.lost_connection_count, 0);
    }

    #[test]
    fn connection_manager_start() {
        let _temp_config = make_temp_config(None);

        let (cm_tx, cm_rx) = channel();

        let mut cm = Service::new_inactive(cm_tx).unwrap();

        let cm_listen_ep = cm.start_accepting(Port::Tcp(0)).unwrap();

        let thread = spawn(move || {
            loop {
                let event = match cm_rx.recv() {
                    Ok(event) => event,
                    Err(_) => break,
                };

                match event {
                    Event::NewMessage(_, _) => {
                    },
                    Event::OnConnect(_) => {
                    },
                    Event::OnAccept(_) => {
                    },
                    Event::LostConnection(_) => {
                        break;
                    },
                    Event::BootstrapFinished => {},
                    Event::ExternalEndpoints(_) => {},
                }
            }
        });

        let _ = spawn(move || {
            let _temp_config = make_temp_config(None);
            let (cm_aux_tx, _) = channel();
            let cm_aux = Service::new_inactive(cm_aux_tx).unwrap();
            // setting the listening port to be greater than 4455 will make the test hanging
            // changing this to cm_beacon_addr will make the test hanging
            cm_aux.connect(vec![cm_listen_ep]);
        }).join();
        thread::sleep_ms(100);

        let _ = thread.join();
    }
}
