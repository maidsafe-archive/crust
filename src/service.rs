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
use std::net;
use std::thread::JoinHandle;
use std::sync::{Arc, Mutex};
use std::str::FromStr;

use std::net::{UdpSocket, Ipv4Addr, TcpListener};
use beacon;
use config_handler::{Config, read_config_file};
use get_if_addrs::{getifaddrs, filter_loopback};
use transport::Handshake;
use endpoint::{Endpoint, Protocol};
use map_external_port::async_map_external_port;
use connection::Connection;

use state::{Closure, State};
use event::{Event, HolePunchResult};
use socket_addr::{SocketAddr, SocketAddrV4};

/// Type used to represent serialised data in a message.
pub type Bytes = Vec<u8>;

/// A structure representing a connection manager.
///
/// This abstraction has a hidden dependency on a config file. Refer to [the docs for `FileHandler`]
/// (../file_handler/struct.FileHandler.html) and [an example config file flowchart]
/// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf) for more
/// information.
pub struct Service {
    beacon_guid_and_port: Option<(beacon::GUID, u16)>,
    config: Config,
    cmd_sender: Sender<Closure>,
    state_thread_handle: Option<JoinHandle<()>>,
}

impl Service {
    /// Constructs a service. User needs to create an asynchronous channel, and provide
    /// the sender half to this method. Receiver will receive all `Event`s from this library.
    pub fn new(event_sender: ::CrustEventSender) -> Result<Service, ::error::Error> {
        let config = match read_config_file() {
            Ok(cfg) => cfg,
            Err(e) => {
                debug!("Crust failed to read config file; Error: {:?};", e);
                try!(::config_handler::create_default_config_file());
                Config::make_default()
            }
        };

        Service::construct(event_sender, config)
    }

    fn construct(event_sender: ::CrustEventSender,
                 config: Config)
                 -> Result<Service, ::error::Error> {
        let mut state = try!(State::new(event_sender));
        let cmd_sender = state.cmd_sender.clone();

        let handle = try!(Self::new_thread("run loop", move || {
            state.run();
        }));

        let service = Service {
            beacon_guid_and_port: None,
            config: config,
            cmd_sender: cmd_sender,
            state_thread_handle: Some(handle),
        };

        Ok(service)
    }

    /// Start the beaconing on port `udp_port`. If port number is 0, the OS will
    /// pick one randomly. The actual port used will be returned.
    ///
    /// This function MUST NOT be called more than once. Currently crust has a
    /// limit of listenning at most once per process.
    pub fn start_beacon(&mut self, udp_port: u16) -> io::Result<u16> {
        self.start_broadcast_acceptor(udp_port)
    }

    /// Starts accepting on a given port. If port number is 0, the OS
    /// will pick one randomly. The actual port used will be returned.
    pub fn start_accepting(&mut self, port: u16) -> io::Result<Endpoint> {
        let acceptor = try!(TcpListener::bind(("0.0.0.0", port)));
        let accept_addr = try!(acceptor.local_addr());

        Self::accept(self.cmd_sender.clone(), acceptor);

        // TODO Take this out after evaluating
        if self.beacon_guid_and_port.is_some() {
            let contacts = filter_loopback(getifaddrs())
                               .into_iter()
                               .map(|ip| {
                                   Endpoint::new(Protocol::Utp, ip.addr.clone(), accept_addr.port())
                               })
                               .collect::<Vec<_>>();

            Self::post(&self.cmd_sender, move |state: &mut State| {
                state.update_bootstrap_contacts(contacts, vec![]);
            });
        }

        // FIXME: Instead of hardcoded wrapping in loopback V4, the
        // acceptor should tell us the address it is accepting on.
        Ok(Endpoint::from_socket_addr(Protocol::Tcp, SocketAddr(accept_addr)))
    }

    #[cfg(test)]
    pub fn start_accepting_utp(&mut self, port: u16) -> io::Result<Endpoint> {
        use utp::UtpListener;
        let acceptor = try!(UtpListener::bind(("0.0.0.0", port)));
        let accept_addr = try!(acceptor.local_addr());

        Self::accept_utp(self.cmd_sender.clone(), acceptor);

        // FIXME: Instead of hardcoded wrapping in loopback V4, the
        // acceptor should tell us the address it is accepting on.
        Ok(Endpoint::from_socket_addr(Protocol::Utp, SocketAddr(accept_addr)))
    }

    fn start_broadcast_acceptor(&mut self, beacon_port: u16) -> io::Result<u16> {
        let acceptor = try!(beacon::BroadcastAcceptor::new(beacon_port));
        let b_port = acceptor.beacon_port();

        // Right now we expect this function to succeed only once.
        assert!(self.beacon_guid_and_port.is_none());
        self.beacon_guid_and_port = Some((acceptor.beacon_guid(), b_port));

        let sender = self.cmd_sender.clone();

        let thread_result = Self::new_thread("beacon acceptor", move || {
            while let Ok((h, t)) = acceptor.accept() {
                let _ = sender.send(Closure::new(move |state: &mut State| {
                    let _ = state.handle_accept(h, t);
                }));
            }
        });

        // TODO: Handle gracefuly.
        assert!(thread_result.is_ok());

        Ok(b_port)
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
    pub fn bootstrap(&mut self, token: u32, beacon_port: Option<u16>) {
        self.bootstrap_with_blacklist(token, beacon_port, &[])
    }

    /// Same as bootstrap, but allows to specify a blacklist of endpoints
    /// this service should never connect to.
    pub fn bootstrap_with_blacklist(&mut self,
                                    token: u32,
                                    beacon_port: Option<u16>,
                                    blacklist: &[Endpoint]) {
        let config = self.config.clone();
        let beacon_guid_and_port = self.beacon_guid_and_port.clone();
        let blist = blacklist.to_vec();

        Self::post(&self.cmd_sender, move |state: &mut State| {
            let mut contacts = state.populate_bootstrap_contacts(&config,
                                                                 beacon_port,
                                                                 &beacon_guid_and_port);

            contacts.retain(|endpoint| !blist.contains(&endpoint));

            state.bootstrap_off_list(token, contacts.clone());
        });
    }

    /// Stop the bootstraping procedure
    pub fn stop_bootstrap(&mut self) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            state.stop_bootstrap();
        });
    }

    /// Remove endpoint from the bootstrap cache.
    pub fn remove_bootstrap_contact(&mut self, endpoint: Endpoint) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            state.update_bootstrap_contacts(vec![], vec![endpoint]);
        });
    }

    // This should be called before destroying an instance of a Service to allow the
    // listener threads to join.  Once called, the Service should be destroyed.
    fn stop(&mut self) {
        use std::net::TcpStream;
        use utp::UtpSocket;

        if let Some(beacon_guid_and_port) = self.beacon_guid_and_port.take() {
            beacon::BroadcastAcceptor::stop(&beacon_guid_and_port);
        }

        let _ = self.cmd_sender.send(Closure::new(move |state: &mut State| {
            state.stop();

            // Connect to our listening ports, this should unblock
            // the threads.
            for port in &state.listening_ports {
                let _ = TcpStream::connect(net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1),
                                                                  port.clone()));
                let _ = UtpSocket::connect(net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1),
                                                                  port.clone()));
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
    pub fn connect(&self, token: u32, endpoints: Vec<Endpoint>) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            let cmd_sender = state.cmd_sender.clone();

            let handshake = Handshake {
                mapper_port: Some(state.mapper.listening_addr().port()),
                external_ip: state.mapper.external_address(),
                remote_ip: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
            };

            let _ = Self::new_thread("connect", move || {
                for endpoint in endpoints {
                    match State::connect(handshake.clone(), endpoint) {
                        Ok((h, t)) => {
                            let _ = cmd_sender.send(Closure::new(move |state: &mut State| {
                                let _ = state.handle_connect(token, h, t);
                            }));
                        }
                        Err(e) => {
                            let _ = cmd_sender.send(Closure::new(move |state: &mut State| {
                                let _ = state.event_sender.send(Event::OnConnect(Err(e), token));
                            }));
                        }
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
    pub fn rendezvous_connect(&self,
                              udp_socket: UdpSocket,
                              token: u32,
                              public_endpoint: Endpoint /* of B */) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            let cmd_sender = state.cmd_sender.clone();

            let handshake = Handshake {
                mapper_port: Some(state.mapper.listening_addr().port()),
                external_ip: state.mapper.external_address(),
                remote_ip: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
            };

            let _ = Self::new_thread("rendezvous connect", move || {
                match State::rendezvous_connect(handshake.clone(), udp_socket, public_endpoint) {
                    Ok((h, t)) => {
                        let _ = cmd_sender.send(Closure::new(move |state: &mut State| {
                            let _ = state.handle_rendezvous_connect(token, h, t);
                        }));
                    }
                    Err(e) => {
                        let _ = cmd_sender.send(Closure::new(move |state: &mut State| {
                            let _ = state.event_sender
                                         .send(Event::OnRendezvousConnect(Err(e), token));
                        }));
                    }
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

    fn accept(cmd_sender: Sender<Closure>, acceptor: TcpListener) {
        let cmd_sender2 = cmd_sender.clone();

        Self::post(&cmd_sender, move |state: &mut State| {
            let port = acceptor.local_addr().unwrap().port();
            state.listening_ports.insert(port);

            let handshake = Handshake {
                mapper_port: Some(state.mapper.listening_addr().port()),
                external_ip: state.mapper.external_address(),
                remote_ip: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
            };

            let _ = Self::new_thread("listen", move || {
                let accept_result = State::accept(handshake, &acceptor);
                let cmd_sender3 = cmd_sender2.clone();

                let _ = cmd_sender2.send(Closure::new(move |state: &mut State| {
                    state.listening_ports.remove(&port);

                    if state.stop_called {
                        return;
                    }

                    match accept_result {
                        Ok((handshake, transport)) => {
                            let _ = state.handle_accept(handshake, transport);
                        }
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

    #[cfg(test)]
    fn accept_utp(cmd_sender: Sender<Closure>, acceptor: ::utp::UtpListener) {
        let cmd_sender2 = cmd_sender.clone();

        Self::post(&cmd_sender, move |state: &mut State| {
            let port = acceptor.local_addr().unwrap().port();
            state.listening_ports.insert(port);

            let handshake = Handshake {
                mapper_port: Some(state.mapper.listening_addr().port()),
                external_ip: state.mapper.external_address(),
                remote_ip: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
            };

            let _ = Self::new_thread("listen-utp", move || {
                let accept_result = State::accept_utp(handshake, &acceptor);
                let cmd_sender3 = cmd_sender2.clone();

                let _ = cmd_sender2.send(Closure::new(move |state: &mut State| {
                    state.listening_ports.remove(&port);

                    if state.stop_called {
                        return;
                    }

                    match accept_result {
                        Ok((handshake, transport)) => {
                            let _ = state.handle_accept(handshake, transport);
                        }
                        Err(_) => {
                            // TODO: What now? Stop? Start again?
                            panic!();
                        }
                    }

                    Self::accept_utp(cmd_sender3, acceptor);
                }));
            });
        })
    }

    /// Initiates uPnP port mapping of the currently used accepting endpoints.
    /// On success ExternalEndpoint event is generated containg our external
    /// endpoints.
    pub fn get_external_endpoints(&self) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            type T = (SocketAddrV4, Endpoint);

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

                async_map_external_port(internal_ep.clone(), move |results: io::Result<Vec<T>>| {
                    let mut async = async.lock().unwrap();
                    async.remaining -= 1;
                    if let Ok(results) = results {
                        for result in results {
                            let transport_port = internal_ep.socket_addr().port();
                            let ext_ep = Endpoint::new(result.1.protocol().clone(),
                                                       result.1.ip().clone(),
                                                       transport_port);
                            async.results.push(ext_ep);
                        }
                    }
                    if async.remaining == 0 {
                        let event = Event::ExternalEndpoints(async.results
                                                                  .clone());
                        let _ = event_sender.send(event);
                    }
                });
            }
        });
    }

    /// Lookup a mapped udp socket based on result_token
    pub fn get_mapped_udp_socket(&self, result_token: u32) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            state.get_mapped_udp_socket(result_token);
        });
    }

    fn new_thread<F, T>(name: &str, f: F) -> io::Result<JoinHandle<T>>
        where F: FnOnce() -> T,
              F: Send + 'static,
              T: Send + 'static
    {
        thread::Builder::new()
            .name("Service::".to_owned() + name)
            .spawn(f)
    }

    fn post<F>(sender: &Sender<Closure>, cmd: F)
        where F: FnOnce(&mut State) + Send + 'static
    {
        assert!(sender.send(Closure::new(cmd)).is_ok());
    }

    /// Udp hole punching process
    pub fn udp_punch_hole(&self,
                          result_token: u32,
                          udp_socket: UdpSocket,
                          secret: Option<[u8; 4]>,
                          peer_addr: SocketAddr) {
        Self::post(&self.cmd_sender, move |state: &mut State| {
            let event_sender = state.event_sender.clone();

            // TODO (canndrew): we currently have no means to handle this error
            let _ = Self::new_thread("udp_punch_hole", move || {
                let (udp_socket, result_addr) =
                    ::hole_punching::blocking_udp_punch_hole(udp_socket, secret, peer_addr);

                // TODO (canndrew): we currently have no means to handle this error
                let _ = event_sender.send(Event::OnHolePunched(HolePunchResult {
                    result_token: result_token,
                    udp_socket: udp_socket,
                    peer_addr: result_addr,
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
    use std::fs::remove_file;
    use std::io;
    use std::net::{UdpSocket, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::mpsc::{Sender, Receiver, channel};
    use std::thread;
    use std::thread::spawn;
    use std::net;
    use rustc_serialize::{Decodable, Encodable};
    use cbor::{Decoder, Encoder};
    use connection::Connection;
    use endpoint::{Protocol, Endpoint};
    use config_handler::write_config_file;
    use event::Event;
    use bootstrap_handler::BootstrapHandler;
    use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
    use socket_addr::SocketAddr;

    type CategoryRx = ::std::sync::mpsc::Receiver<MaidSafeEventCategory>;

    fn encode<T>(value: &T) -> Bytes
        where T: Encodable
    {
        let mut enc = Encoder::from_memory();
        let _ = enc.encode(&[value]);
        enc.into_bytes()
    }

    #[allow(dead_code)]
    fn decode<T>(bytes: &[u8]) -> T
        where T: Decodable
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
        pub path: PathBuf,
    }

    impl Drop for TestConfigFile {
        fn drop(&mut self) {
            let _ = remove_file(&self.path);
        }
    }

    fn make_temp_config() -> TestConfigFile {
        make_temp_config_with_endpoints(&[])
    }

    fn make_temp_config_with_endpoints(endpoints: &[Endpoint]) -> TestConfigFile {
        let path = write_config_file(Some(endpoints.to_vec())).unwrap();
        TestConfigFile { path: path }
    }

    fn filter_ok<T>(vec: Vec<io::Result<T>>) -> Vec<T> {
        vec.into_iter().filter_map(|a| a.ok()).collect()
    }

    fn unspecified_to_loopback(eps: &[Endpoint]) -> Vec<Endpoint> {
        eps.iter().map(|elt| elt.unspecified_to_loopback()).collect()
    }

    #[test]
    fn bootstrap() {
        BootstrapHandler::cleanup().unwrap();

        let _cleaner = ::file_handler::ScopedUserAppDirRemover;
        let (category_tx, _) = channel();
        let (cm1_i, _) = channel();
        let _config_file = make_temp_config();

        let crust_event_category = MaidSafeEventCategory::CrustEvent;
        let event_sender1 = MaidSafeObserver::new(cm1_i,
                                                  crust_event_category.clone(),
                                                  category_tx.clone());

        let mut cm1 = Service::new(event_sender1).unwrap();
        let cm1_ports = filter_ok(vec![cm1.start_accepting(0)]);
        let beacon_port = cm1.start_beacon(0).unwrap();
        assert_eq!(cm1_ports.len(), 1);
        assert_eq!(Some(beacon_port), cm1.get_beacon_acceptor_port());

        thread::sleep(::std::time::Duration::from_secs(1));
        let _config_file = make_temp_config();

        let (cm2_i, cm2_o) = channel();
        let event_sender2 = MaidSafeObserver::new(cm2_i, crust_event_category, category_tx);
        let mut cm2 = Service::new(event_sender2).unwrap();

        cm2.bootstrap(0, Some(beacon_port));

        let timeout = ::time::Duration::seconds(5);
        let start = ::time::now();
        let mut result = Err(::std::sync::mpsc::TryRecvError::Empty);
        while ::time::now() < start + timeout && result.is_err() {
            result = cm2_o.try_recv();
            ::std::thread::sleep(::std::time::Duration::from_millis(100));
        }
        match result {
            Ok(Event::OnConnect(conn, _)) => {
                debug!("OnConnect {:?}", conn);
            }
            Ok(Event::OnAccept(addr, ep)) => {
                debug!("OnAccept {:?} {:?}", addr, ep);
            }
            _ => assert!(false, "Failed to receive NewConnection event"),
        }

        drop(cm1);
        drop(cm2);
    }

    // #[test]
    // fn bootstrap_with_blacklist() {
    //     BootstrapHandler::cleanup().unwrap();
    //
    //     let (ignored_category_tx, _) = channel();
    //     let (ignored_event_tx, _) = channel();
    //
    //     let (category_tx, category_rx) = channel();
    //     let (event_tx, event_rx) = channel();
    //
    //     let event_sender0 = MaidSafeObserver::new(ignored_event_tx.clone(),
    //                                               MaidSafeEventCategory::CrustEvent,
    //                                               ignored_category_tx.clone());
    //
    //     let event_sender1 = MaidSafeObserver::new(ignored_event_tx,
    //                                               MaidSafeEventCategory::CrustEvent,
    //                                               ignored_category_tx);
    //
    //     let event_sender2 = MaidSafeObserver::new(event_tx,
    //                                               MaidSafeEventCategory::CrustEvent,
    //                                               category_tx);
    //
    //
    //
    //     // Start accepting on these two services and keep their endpoints.
    //     let mut service0 = Service::new(event_sender0).unwrap();
    //     let mut service1 = Service::new(event_sender1).unwrap();
    //
    //     let endpoints = unspecified_to_loopback(vec![service0.start_accepting(Port::Tcp(0))
    //                                                          .unwrap(),
    //                                                  service1.start_accepting(Port::Tcp(0))
    //                                                          .unwrap()]);
    //
    //     // Write those endpoints to the config file, so the next service will
    //     // try to connect to them.
    //     let _config_file = make_temp_config_with_endpoints(&endpoints);
    //
    //     // Bootstrap another service but blacklist one of the endpoints in the
    //     // config file.
    //     let blacklisted_endpoint = endpoints[0];
    //     let mut service2 = Service::new(event_sender2).unwrap();
    //     service2.bootstrap_with_blacklist(0, None, &[blacklisted_endpoint]);
    //
    //     let mut connected_endpoints = Vec::new();
    //
    //     for category in category_rx.iter() {
    //         match category {
    //             MaidSafeEventCategory::CrustEvent => {
    //                 match event_rx.try_recv() {
    //                     Ok(Event::BootstrapFinished) => break,
    //                     Ok(Event::OnConnect(Ok((_, conn)), _)) => {
    //                         connected_endpoints.push(conn.peer_endpoint());
    //                     }
    //                     event => println!("event: {:?}", event),
    //                 }
    //             }
    //
    //             _ => unreachable!("This category should not have been fired - {:?}", category),
    //         }
    //     }
    //
    //     // Test that the third service did not connect to the blacklisted
    //     // endpoints.
    //     assert!(!connected_endpoints.is_empty());
    //
    //     for endpoint in connected_endpoints {
    //         assert!(endpoint != blacklisted_endpoint);
    //     }
    // }

    #[test]
    fn connection_manager() {
        BootstrapHandler::cleanup().unwrap();

        let run_cm = |cm: Service, o: Receiver<Event>, category_rx: CategoryRx| {
            spawn(move || {
                for it in category_rx.iter() {
                    match it {
                        MaidSafeEventCategory::CrustEvent => {
                            if let Ok(event) = o.try_recv() {
                                match event {
                                    Event::OnConnect(Ok((_, other_ep)), _) => {
                                        cm.send(other_ep.clone(),
                                                encode(&"hello world".to_owned()));
                                    }
                                    Event::OnAccept(_, other_ep) => {
                                        cm.send(other_ep.clone(),
                                                encode(&"hello world".to_owned()));
                                    }
                                    Event::NewMessage(_, _) => {
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => unreachable!("This category should not have been fired - {:?}", it),
                    }
                }
            })
        };

        let mut temp_configs = vec![make_temp_config()];

        let (category_tx, category_rx0) = channel();
        let (cm1_i, cm1_o) = channel();
        let crust_event_category = MaidSafeEventCategory::CrustEvent;
        let event_sender1 = MaidSafeObserver::new(cm1_i, crust_event_category.clone(), category_tx);
        let mut cm1 = Service::new(event_sender1).unwrap();
        let cm1_eps = filter_ok(vec![cm1.start_accepting(0)]);
        assert!(cm1_eps.len() >= 1);

        temp_configs.push(make_temp_config());

        let (cm2_i, cm2_o) = channel();
        let (category_tx, category_rx1) = channel();
        let event_sender2 = MaidSafeObserver::new(cm2_i, crust_event_category, category_tx);
        let mut cm2 = Service::new(event_sender2).unwrap();
        let cm2_eps = filter_ok(vec![cm2.start_accepting(0)]);
        assert!(cm2_eps.len() >= 1);

        cm2.connect(0, unspecified_to_loopback(&cm1_eps));
        cm1.connect(1, unspecified_to_loopback(&cm2_eps));

        let runner1 = run_cm(cm1, cm1_o, category_rx0);
        let runner2 = run_cm(cm2, cm2_o, category_rx1);

        assert!(runner1.join().is_ok());
        assert!(runner2.join().is_ok());
    }

    #[test]
    fn rendezvous_connection() {
        BootstrapHandler::cleanup().unwrap();

        // Wait 2 seconds until previous bootstrap test ends. If not, that test connects to these endpoints.
        thread::sleep(::std::time::Duration::from_secs(2));
        let run_cm = |cm: Service,
                      o: Receiver<Event>,
                      category_rx: CategoryRx,
                      shutdown_recver: Receiver<()>,
                      ready_sender: Sender<()>| {
            spawn(move || {
                for it in category_rx.iter() {
                    match it {
                        ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent => {
                            match o.try_recv() {
                                Ok(event) => {
                                    match event {
                                        Event::OnRendezvousConnect(Ok((_, other_ep)), _) => {
                                            cm.send(other_ep.clone(),
                                                    encode(&"hello world".to_owned()));
                                        }
                                        Event::OnRendezvousConnect(Err(_), _) => {
                                            panic!("Cannot establish rendezvous connection");
                                        }
                                        Event::NewMessage(_, _) => break,
                                        _ => (),
                                    }
                                }
                                Err(::std::sync::mpsc::TryRecvError::Disconnected) => break,
                                _ => (),
                            }
                        }
                        _ => unreachable!("This category should not have been fired - {:?}", it),
                    }
                }

                let _ = ready_sender.send(());
                let _ = shutdown_recver.recv();
            })
        };

        let mut temp_configs = vec![make_temp_config()];

        let (category_tx, category_rx0) = channel();
        let (cm1_i, cm1_o) = channel();
        let crust_event_category =
            ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent;
        let event_sender1 =
            ::maidsafe_utilities::event_sender::MaidSafeObserver::new(cm1_i,
                                                                      crust_event_category.clone(),
                                                                      category_tx);
        let cm1 = Service::new(event_sender1).unwrap();

        temp_configs.push(make_temp_config());

        let (cm2_i, cm2_o) = channel();
        let (category_tx, category_rx1) = channel();
        let event_sender2 =
            ::maidsafe_utilities::event_sender::MaidSafeObserver::new(cm2_i,
                                                                      crust_event_category,
                                                                      category_tx);
        let cm2 = Service::new(event_sender2).unwrap();

        let peer1_udp_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let peer2_udp_socket = UdpSocket::bind("0.0.0.0:0").unwrap();

        let peer1_port = peer1_udp_socket.local_addr().unwrap().port();
        let peer1_addr =
            SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1),
                                                                  peer1_port)));

        let peer2_port = peer2_udp_socket.local_addr().unwrap().port();
        let peer2_addr =
            SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1),
                                                                  peer2_port)));

        cm2.rendezvous_connect(peer1_udp_socket,
                               0,
                               Endpoint::from_socket_addr(Protocol::Utp, peer2_addr));
        cm1.rendezvous_connect(peer2_udp_socket,
                               0,
                               Endpoint::from_socket_addr(Protocol::Utp, peer1_addr));

        let (ready_tx1, ready_rx1) = channel();
        let (shut_tx1, shut_rx1) = channel();
        let (ready_tx2, ready_rx2) = channel();
        let (shut_tx2, shut_rx2) = channel();

        let runner1 = run_cm(cm1, cm1_o, category_rx0, shut_rx1, ready_tx1);
        let runner2 = run_cm(cm2, cm2_o, category_rx1, shut_rx2, ready_tx2);

        let _ = ready_rx1.recv();
        let _ = ready_rx2.recv();
        let _ = shut_tx1.send(());
        let _ = shut_tx2.send(());

        assert!(runner1.join().is_ok());
        assert!(runner2.join().is_ok());
    }

    fn test_network(protocol: Protocol) {
        BootstrapHandler::cleanup().unwrap();

        const NETWORK_SIZE: u32 = 10;
        const MESSAGE_PER_NODE: u32 = 5;
        const TOTAL_MSG_TO_RECEIVE: u32 = MESSAGE_PER_NODE * (NETWORK_SIZE - 1);

        struct Node {
            _id: u32,
            service: Service,
            reader: Receiver<Event>,
            category_rx: ::std::sync::mpsc::Receiver<::maidsafe_utilities::event_sender::MaidSafeEventCategory>,
        }

        impl Node {
            fn new(id: u32) -> Node {
                let (category_tx, category_rx) = channel();
                let (writer, reader) = channel();
                let crust_event_category =
                    ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent;
                let event_sender1 =
                    ::maidsafe_utilities::event_sender::MaidSafeObserver::new(writer,
                                                                              crust_event_category,
                                                                              category_tx);
                Node {
                    _id: id,
                    service: Service::new(event_sender1).unwrap(),
                    reader: reader,
                    category_rx: category_rx,
                }
            }

            fn run(&mut self) -> Stats {
                let mut stats = Stats::new();

                for it in self.category_rx.iter() {
                    match it {
                        ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent => {
                            if let Ok(event) = self.reader.try_recv() {
                                match event {
                                    Event::OnConnect(Ok((_, connection)), _) => {
                                        stats.connect_count += 1;
                                        self.send_data_to(connection);
                                    }
                                    Event::OnAccept(_, connection) => {
                                        stats.accept_count += 1;
                                        self.send_data_to(connection);
                                    }
                                    Event::NewMessage(_from, _bytes) => {
                                        stats.messages_count += 1;
                                        // let msg = decode::<String>(&bytes);
                                        if stats.messages_count == TOTAL_MSG_TO_RECEIVE {
                                            break;
                                        }
                                    }
                                    Event::LostConnection(_) => {}
                                    _ => {
                                        println!("Received event {:?}", event);
                                    }
                                }
                            }
                        }
                        _ => unreachable!("This category should not have been fired - {:?}", it),
                    }
                }
                stats
            }

            fn send_data_to(&self, connection: Connection) {
                for i in 0..MESSAGE_PER_NODE {
                    let msg = format!("MESSAGE {}", i);
                    self.service.send(connection.clone(), encode(&msg));
                }
            }
        }

        let mut nodes = (0..NETWORK_SIZE)
                            .map(Node::new)
                            .collect::<Vec<_>>();

        let mut runners = Vec::new();

        let mut listening_eps = nodes.iter_mut()
                                     .map(|node| {
                                         match protocol {
                                             Protocol::Tcp => node.service.start_accepting(0).unwrap(),
                                             Protocol::Utp => node.service.start_accepting_utp(0).unwrap(),
                                         }
                                     })
                                     .map(|ep| ep.unspecified_to_loopback())
                                     .collect::<::std::collections::VecDeque<_>>();

        for mut node in nodes {
            assert!(listening_eps.pop_front().is_some());

            for ep in &listening_eps {
                node.service.connect(0, vec![ep.clone()]);
            }

            runners.push(spawn(move || node.run()));
        }

        let mut stats = Stats::new();

        for runner in runners {
            let s = runner.join().unwrap();
            stats.add(s)
        }

        assert_eq!(stats.connect_count, NETWORK_SIZE * (NETWORK_SIZE - 1) / 2);
        assert_eq!(stats.accept_count, NETWORK_SIZE * (NETWORK_SIZE - 1) / 2);
        assert_eq!(stats.messages_count,
                   NETWORK_SIZE * (NETWORK_SIZE - 1) * MESSAGE_PER_NODE);
    }

    #[test]
    fn test_network_tcp() {
        test_network(Protocol::Tcp);
    }

    #[test]
    fn test_network_utp() {
        test_network(Protocol::Utp);
    }

    #[test]
    fn connection_manager_start() {
        BootstrapHandler::cleanup().unwrap();

        let _temp_config = make_temp_config();

        let (cm_tx, cm_rx) = channel();
        let (category_tx, category_rx) = channel();

        let crust_event_category =
            ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent;
        let cloned_crust_event_category = crust_event_category.clone();

        let event_sender =
            ::maidsafe_utilities::event_sender::MaidSafeObserver::new(cm_tx,
                                                                      crust_event_category,
                                                                      category_tx);
        let mut cm = Service::new(event_sender).unwrap();

        let cm_listen_ep = cm.start_accepting(0).unwrap();

        let thread = spawn(move || {
            for it in category_rx.iter() {
                match it {
                    ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent => {
                        if let Ok(event) = cm_rx.try_recv() {
                            if let Event::LostConnection(_) = event {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    _ => unreachable!("This category should not have been fired - {:?}", it),
                }
            }
        });

        let _ = spawn(move || {
            let _temp_config = make_temp_config();
            let (category_tx, category_rx) = channel();
            let (cm_aux_tx, cm_aux_rx) = channel();
            let event_sender = ::maidsafe_utilities::event_sender::MaidSafeObserver::new(cm_aux_tx,
                                                                                         cloned_crust_event_category,
                                                                                         category_tx);
            let cm_aux = Service::new(event_sender).unwrap();
        // setting the listening port to be greater than 4455 will make the test hanging
        // changing this to cm_beacon_addr will make the test hanging
            cm_aux.connect(0, unspecified_to_loopback(&vec![cm_listen_ep]));

            for it in category_rx.iter() {
                match it {
                    ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent => {
                        if let Ok(event) = cm_aux_rx.try_recv() {
                            if let Event::OnConnect(_, _) = event {
                                break;
                            }
                        } else {
                            break;
                        }
                    },
                    _ => unreachable!("This category should not have been fired - {:?}", it),
                }
            }
        }).join();
        thread::sleep(::std::time::Duration::from_millis(100));

        let _ = thread.join();
    }

    #[test]
    fn reaccept() {
        BootstrapHandler::cleanup().unwrap();

        let tcp_port;
        let utp_port;

        let (category_tx, _) = channel();
        let crust_event_category = MaidSafeEventCategory::CrustEvent;

        {
            let (sender, _) = channel();
            let event_sender1 = MaidSafeObserver::new(sender,
                                                      crust_event_category.clone(),
                                                      category_tx.clone());
            let mut service = Service::new(event_sender1).unwrap();
            // random port assigned by os
            tcp_port = unwrap_result!(service.start_accepting(0)).port();
            utp_port = unwrap_result!(service.start_accepting(0)).port();
        }

        {
            let (sender, _) = channel();
            let crust_event_category = MaidSafeEventCategory::CrustEvent;
            let event_sender1 = MaidSafeObserver::new(sender, crust_event_category, category_tx);
            let mut service = Service::new(event_sender1).unwrap();
            // reuse the ports from above
            let _ = service.start_accepting(tcp_port).unwrap();
            let _ = service.start_accepting(utp_port).unwrap();
        }
    }

    // #[test]
    // fn remove_bootstrap_contact() {
    //     let endpoint0 = Endpoint::tcp("250.0.0.1:55555");
    //     let endpoint1 = Endpoint::tcp("250.0.0.2:55556");
    //
    //     BootstrapHandler::cleanup().unwrap();
    //     let mut cache = BootstrapHandler::new();
    //     cache.update_contacts(vec![endpoint0, endpoint1], vec![]).unwrap();
    //
    //     {
    //         let (category_tx, _) = channel();
    //         let (event_tx, _) = channel();
    //         let event_sender = MaidSafeObserver::new(event_tx,
    //                                                  MaidSafeEventCategory::CrustEvent,
    //                                                  category_tx);
    //         let mut service = Service::new(event_sender).unwrap();
    //         service.remove_bootstrap_contact(endpoint0);
    //
    //         // The nested scope here causes the service to be dropped which
    //         // joins all its internal threads. This is to make sure all
    //         // asynchronous operations are completed before we continue.
    //     }
    //
    //     let contacts = cache.read_file().unwrap();
    //     assert!(!contacts.contains(&endpoint0));
    // }
}
