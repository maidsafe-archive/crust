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

use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use beacon;
use bootstrap_handler::BootstrapHandler;
use config_handler::{Config, read_config_file};
use getifaddrs::{getifaddrs, filter_loopback};
use transport;
use transport::{Endpoint, Port, Handshake};
use ip;
use map_external_port::async_map_external_port;
use connection::Connection;

use state::State;
use event::{Event, HolePunchResult};
use util::SocketAddrV4W;

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
    state_thread_handle  : Option<JoinHandle<()>>,
}

impl Service {
    /// Constructs a service. User needs to create an asynchronous channel, and provide
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

    /// Construct a service. As with the `Service::new` function, but will not
    /// implicitly start any network activity. This construtor is intended
    /// only for testing purposes.
    pub fn new_inactive(event_sender: Sender<Event>)
            -> io::Result<Service> {
        Service::construct(event_sender, Config::make_zero())
    }

    fn construct(event_sender: Sender<Event>, config: Config)
            -> io::Result<Service> {
        let mut state = try!(State::new(event_sender));
        let cmd_sender = state.cmd_sender.clone();

        let handle = try!(Self::new_thread("run loop", move || state.run() ));

        let mut service = Service {
                              beacon_guid_and_port : None,
                              config               : config,
                              cmd_sender           : cmd_sender,
                              state_thread_handle  : Some(handle)
                          };

        let beacon_port = service.config.beacon_port.clone();

        if let Some(port) = beacon_port {
            let _ = service.start_broadcast_acceptor(port);
        }

        Ok(service)
    }

    /// Start accepting on ports defined in the config file. Returns
    /// a vector of Ok(endpoint) for endpoints where the accetation
    /// started successfully.
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

    /// Starts accepting on a given port. If port number is 0, the OS
    /// will pick one randomly. The actual port used will be returned.
    pub fn start_accepting(&mut self, port: Port) -> io::Result<Endpoint> {
        let acceptor = try!(transport::Acceptor::new(port));
        let accept_addr = acceptor.local_addr();

        Self::accept(self.cmd_sender.clone(), acceptor);

        if self.beacon_guid_and_port.is_some() {
            let contacts = filter_loopback(getifaddrs()).into_iter()
                .map(|ip| { Endpoint::new(ip.addr.clone(), accept_addr.get_port()) })
                .collect::<Vec<_>>();

            Self::post(&self.cmd_sender, move |state : &mut State| {
                state.update_bootstrap_contacts(contacts);
            });
        }

        // FIXME: Instead of hardcoded wrapping in loopback V4, the
        // acceptor should tell us the address it is accepting on.
        Ok(accept_addr)
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
        use std::net::TcpStream;
        use utp::UtpSocket;

        if let Some(beacon_guid_and_port) = self.beacon_guid_and_port {
            beacon::BroadcastAcceptor::stop(&beacon_guid_and_port);
            self.beacon_guid_and_port = None;
        }

        let _ = self.cmd_sender.send(Box::new(move |state: &mut State| {
            state.stop();

            // Connect to our listening ports, this should unblock
            // the threads.
            for port in state.listening_ports.iter() {
                let addr = ::util::loopback_v4(*port).get_address();

                match *port {
                    Port::Tcp(_) => { let _ = TcpStream::connect(&addr); },
                    Port::Utp(_) => { let _ = UtpSocket::connect(&addr); }
                }
            }
        }));

        if let Some(handle) = self.state_thread_handle.take() {
            let _ = handle.join();
        }
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

            let handshake = Handshake {
                mapper_port: Some(state.mapper.listening_addr().port()),
                external_ip: state.mapper.external_address().map(SocketAddrV4W),
            };

            let _ = Self::new_thread("connect", move || {
                for endpoint in endpoints {
                    if let Ok((h, t)) = State::connect(handshake.clone(), endpoint) {
                        let _ = cmd_sender.send(Box::new(move |state: &mut State| {
                            let _ = state.handle_connect(h,
                                                         t,
                                                         is_broadcast_acceptor);
                        }));
                    }
                }
            });
        });
    }

    /// Opens a connection to a remote peer. `public_endpoint` is the endpoint
    /// of the remote peer. `udp_socket` is a socket whose public address will
    /// be used by the other peer.
    ///
    /// A rendezvous connection setup is different to the traditional BSD socket
    /// setup in which there is no client or server side. Both ends create a
    /// socket and send somehow its public address to the other peer. Once both
    /// ends know each other address, both must call this function passing the
    /// socket which possess the address used by the other peer and passing the
    /// other peer's address.
    ///
    /// Only UDP-based protocols are supported. This means that you must use a
    /// uTP endpoint or nothing will happen.
    ///
    /// On success `Event::OnRendezvousConnect` with connected `Endpoint` will
    /// be sent to the event channel. On failure, nothing is reported. Failed
    /// attempts are not notified back up to the caller. If the caller wants to
    /// know of a failed attempt, it must maintain a record of the attempt
    /// itself which times out if a corresponding
    /// `Event::OnRendezvousConnection` isn't received. See also [Process for
    /// Connecting]
    /// (https://github.com/maidsafe/crust/blob/master/docs/connect.md) for
    /// details on handling of connect in different protocols.
    pub fn rendezvous_connect(&self, udp_socket: UdpSocket,
                              public_endpoint: Endpoint /* of B */) {
        Self::post(&self.cmd_sender, move |state : &mut State| {
            let cmd_sender = state.cmd_sender.clone();

            let handshake = Handshake {
                mapper_port: Some(state.mapper.listening_addr().port()),
                external_ip: state.mapper.external_address().map(SocketAddrV4W),
            };

            let _ = Self::new_thread("rendezvous connect", move || {
                if let Ok((h, t)) = State::rendezvous_connect(handshake.clone(),
                                                              udp_socket,
                                                              public_endpoint) {
                    let _ = cmd_sender.send(Box::new(move |state: &mut State| {
                        let _ = state.handle_rendezvous_connect(h, t);
                    }));
                }
            });
        });
    }

    /// Sends a message over a specified connection.
    pub fn send(&self, connection: Connection, message: Bytes) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            state.send(connection, message);
        })
    }

    /// Closes a connection.
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
            let port = acceptor.local_port();
            state.listening_ports.insert(port);

            let handshake = Handshake {
                mapper_port: Some(state.mapper.listening_addr().port()),
                external_ip: state.mapper.external_address().map(SocketAddrV4W),
            };

            let _ = Self::new_thread("listen", move || {
                let accept_result = State::accept(handshake, &acceptor);
                let cmd_sender3 = cmd_sender2.clone();

                let _ = cmd_sender2.send(Box::new(move |state: &mut State| {
                    state.listening_ports.remove(&port);

                    if state.stop_called {
                        return;
                    }

                    match accept_result {
                        Ok((handshake, transport)) => {
                            let _ = state.handle_accept(handshake, transport);
                        },
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

    /// Initiates uPnP port mapping of the currently used accepting endpoints.
    /// On success ExternalEndpoint event is generated containg our external
    /// endpoints.
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

                async_map_external_port(internal_ep.to_ip().clone(),
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

    pub fn get_mapped_udp_socket(&self, result_token: u32) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            state.get_mapped_udp_socket(result_token);
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

    pub fn udp_punch_hole(&self,
                          result_token: u32,
                          udp_socket: UdpSocket,
                          secret: Option<[u8; 4]>,
                          peer_addr: SocketAddr)
    {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            let event_sender = state.event_sender.clone();

            // TODO (canndrew): we currently have no means to handle this error
            let _ = Self::new_thread("udp_punch_hole", move || {
                let (udp_socket, result_addr)
                    = ::hole_punching::blocking_udp_punch_hole(udp_socket,
                                                               secret,
                                                               peer_addr);

                // TODO (canndrew): we currently have no means to handle this error
                let _ = event_sender.send(Event::OnHolePunched(HolePunchResult {
                    result_token: result_token,
                    udp_socket:   udp_socket,
                    peer_addr:    result_addr,
                }));
            });
        });
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
    use transport::Endpoint;
    use connection::Connection;
    use std::thread::spawn;
    use std::thread;
    use std::sync::mpsc::{Sender, Receiver, channel};
    use std::net::{UdpSocket, Ipv4Addr, SocketAddrV4};
    use rustc_serialize::{Decodable, Encodable};
    use cbor::{Decoder, Encoder};
    use transport::Port;
    use config_handler::write_config_file;
    use std::path::PathBuf;
    use std::fs::remove_file;
    use event::Event;
    use std::io;
    use util;

    fn encode<T>(value: &T) -> Bytes where T: Encodable
    {
        let mut enc = Encoder::from_memory();
        let _ = enc.encode(&[value]);
        enc.into_bytes()
    }

    #[allow(dead_code)]
    fn decode<T>(bytes: &Vec<u8>) -> T where T: Decodable
    {
        let mut dec = Decoder::from_bytes(&bytes[..]);
        dec.decode().next().unwrap().unwrap()
    }

    #[derive(Debug)]
    struct Stats {
        connect_count: u32,
        accept_count: u32,
        messages_count: u32,
    }

    impl Stats {
        fn new() -> Stats {
            Stats {
                connect_count: 0,
                accept_count: 0,
                messages_count: 0,
            }
        }

        fn add(&mut self, s: Stats) {
            self.connect_count += s.connect_count;
            self.accept_count += s.accept_count;
            self.messages_count += s.messages_count;
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

    fn loopback_if_unspecified(eps: Vec<Endpoint>) -> Vec<Endpoint> {
        eps.iter().map(|e|e.map_ip_addr(util::loopback_if_unspecified)).collect()
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
                        _ => {},
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

        cm2.connect(loopback_if_unspecified(cm1_eps));
        cm1.connect(loopback_if_unspecified(cm2_eps));

        let runner1 = run_cm(cm1, cm1_o);
        let runner2 = run_cm(cm2, cm2_o);

        assert!(runner1.join().is_ok());
        assert!(runner2.join().is_ok());
    }

    #[test]
    fn rendezvous_connection() {
        // Wait 2 seconds until previous bootstrap test ends. If not, that test connects to these endpoints.
        thread::sleep_ms(2000);
        let run_cm = |cm: Service, o: Receiver<Event>,
                      shutdown_recver: Receiver<()>, ready_sender: Sender<()>| {
            spawn(move || {
                for i in o.iter() {
                    match i {
                        Event::OnRendezvousConnect(other_ep) => {
                            let _ = cm.send(other_ep.clone(),
                                            encode(&"hello world".to_string()));
                        },
                        Event::NewMessage(_, _) => break,
                        _ => (),
                    }
                }

                let _ = ready_sender.send(());
                let _ = shutdown_recver.recv();
            })
        };

        let mut temp_configs = vec![make_temp_config(None)];

        let (cm1_i, cm1_o) = channel();
        let cm1 = Service::new_inactive(cm1_i).unwrap();

        temp_configs.push(make_temp_config(cm1.get_beacon_acceptor_port()));

        let (cm2_i, cm2_o) = channel();
        let cm2 = Service::new_inactive(cm2_i).unwrap();

        let peer1_udp_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let peer2_udp_socket = UdpSocket::bind("0.0.0.0:0").unwrap();

        let peer1_port = peer1_udp_socket.local_addr().unwrap().port();
        let peer1_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1),
                                           peer1_port);

        let peer2_port = peer2_udp_socket.local_addr().unwrap().port();
        let peer2_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1),
                                           peer2_port);

        cm2.rendezvous_connect(peer1_udp_socket, Endpoint::utp(peer2_addr));
        cm1.rendezvous_connect(peer2_udp_socket, Endpoint::utp(peer1_addr));

        let (ready_tx1, ready_rx1) = channel();
        let (shut_tx1, shut_rx1) = channel();
        let (ready_tx2, ready_rx2) = channel();
        let (shut_tx2, shut_rx2) = channel();

        let runner1 = run_cm(cm1, cm1_o, shut_rx1, ready_tx1);
        let runner2 = run_cm(cm2, cm2_o, shut_rx2, ready_tx2);

        let _ = ready_rx1.recv();
        let _ = ready_rx2.recv();
        let _ = shut_tx1.send(());
        let _ = shut_tx2.send(());

        assert!(runner1.join().is_ok());
        assert!(runner2.join().is_ok());
    }

    #[test]
    fn network() {
        const NETWORK_SIZE: u32 = 10;
        const MESSAGE_PER_NODE: u32 = 5;
        const TOTAL_MSG_TO_RECEIVE: u32 = MESSAGE_PER_NODE * (NETWORK_SIZE - 1);

        struct Node {
            _id: u32,
            service: Service,
            reader: Receiver<Event>,
        }

        impl Node {
            fn new(id: u32) -> Node {
                let (writer, reader) = channel();
                Node {
                    _id: id,
                    service: Service::new(writer).unwrap(),
                    reader: reader,
                }
            }

            fn run(&mut self) -> Stats {
                let mut stats = Stats::new();

                for event in self.reader.iter() {
                    match event {
                        Event::OnConnect(connection) => {
                            stats.connect_count += 1;
                            self.send_data_to(connection);
                        },
                        Event::OnAccept(connection) => {
                            stats.accept_count += 1;
                            self.send_data_to(connection);
                        },
                        Event::NewMessage(from, bytes) => {
                            stats.messages_count += 1;
                            //let msg = decode::<String>(&bytes);
                            if stats.messages_count == TOTAL_MSG_TO_RECEIVE {
                                break;
                            }
                        },
                        Event::LostConnection(_) => {
                        },
                        _ => {
                            println!("Received event {:?}", event);
                        }
                    }
                }
                stats
            }

            fn send_data_to(&self, connection: Connection) {
                for i in 0..MESSAGE_PER_NODE {
                    let msg = format!("MESSAGE {}", i);
                    self.service.send(connection, encode(&msg));
                }
            }
        }

        let mut nodes = (0..NETWORK_SIZE)
            .map(|i|Node::new(i))
            .collect::<Vec<_>>();

        let mut runners = Vec::new();

        let mut listening_eps = nodes.iter_mut()
            .map(|node| node.service.start_accepting(Port::Tcp(0)).unwrap())
            .map(|ep| ep.map_ip_addr(::util::loopback_if_unspecified))
            .collect::<::std::collections::LinkedList<_>>();

        for mut node in nodes.into_iter() {
            assert!(listening_eps.pop_front().is_some());

            for ep in listening_eps.iter() {
                node.service.connect(vec![ep.clone()]);
            }

            runners.push(spawn(move || node.run()));
        }

        let mut stats = Stats::new();

        for runner in runners.into_iter() {
            let s = runner.join().unwrap();
            stats.add(s)
        }

        assert_eq!(stats.connect_count,  NETWORK_SIZE * (NETWORK_SIZE - 1) / 2);
        assert_eq!(stats.accept_count,   NETWORK_SIZE * (NETWORK_SIZE - 1) / 2);
        assert_eq!(stats.messages_count, NETWORK_SIZE * (NETWORK_SIZE - 1) * MESSAGE_PER_NODE);
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
                    Event::LostConnection(_) => {
                        break;
                    },
                    _ => {},
                }
            }
        });

        let _ = spawn(move || {
            let _temp_config = make_temp_config(None);
            let (cm_aux_tx, cm_aux_rx) = channel();
            let cm_aux = Service::new_inactive(cm_aux_tx).unwrap();
            // setting the listening port to be greater than 4455 will make the test hanging
            // changing this to cm_beacon_addr will make the test hanging
            cm_aux.connect(loopback_if_unspecified(vec![cm_listen_ep]));

            loop {
                let ev = match cm_aux_rx.recv() {
                    Ok(ev) => ev,
                    Err(_) => break,
                };
                match ev {
                    Event::OnConnect(_) => break,
                    _ => (),
                }
            }
        }).join();
        thread::sleep_ms(100);

        let _ = thread.join();
    }

    #[test]
    fn reaccept() {
        let tcp_port;
        let utp_port;

        {
            let (sender, _) = channel();
            let mut service = Service::new(sender).unwrap();
            // random port assigned by os
            tcp_port = service.start_accepting(Port::Tcp(0)).unwrap().get_port();
            utp_port = service.start_accepting(Port::Utp(0)).unwrap().get_port();
        }

        {
            let (sender, _) = channel();
            let mut service = Service::new(sender.clone()).unwrap();
            // reuse the ports from above
            let _ = service.start_accepting(tcp_port).unwrap();
            let _ = service.start_accepting(utp_port).unwrap();
        }
    }
}
