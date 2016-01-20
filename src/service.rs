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
use std::sync::mpsc;
use std::sync::atomic::{Ordering, AtomicBool};
use std::thread;
use std::net;
use std::thread::JoinHandle;
use std::sync::{Arc, Mutex};
use std::str::FromStr;

use std::net::TcpListener;

use rand;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use itertools::Itertools;
use acceptor::Acceptor;
use beacon;
use config_handler::{Config, read_config_file};
use transport::Handshake;
use transport;
use endpoint::{Endpoint, Protocol};
use map_external_port::async_map_external_port;
use connection::Connection;
use connection_map::ConnectionMap;
use error::Error;
use ip::SocketAddrExt;

use event::{Event, OurContactInfo, TheirContactInfo, ContactInfoResult};
use socket_addr::{SocketAddr, SocketAddrV4};
use bootstrap_handler::BootstrapHandler;
use hole_punching::HolePunchServer;
use sequence_number::SequenceNumber;

/// A structure representing a connection manager.
///
/// This abstraction has a hidden dependency on a config file. Refer to [the docs for `FileHandler`]
/// (../file_handler/struct.FileHandler.html) and [an example config file flowchart]
/// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf) for more
/// information.
pub struct Service {
    beacon_guid_and_port: Option<(beacon::GUID, u16)>,
    config: Config,
    bootstrap_peers: Option<mpsc::Sender<Vec<Endpoint>>>,
    bootstrap_handler: BootstrapHandler,
    acceptors: Vec<Acceptor>,
    mapper: Arc<HolePunchServer>,
    next_punch_sequence: SequenceNumber,
    event_sender: ::CrustEventSender,
    connection_map: Arc<ConnectionMap>,
    is_bootstrapping: Arc<AtomicBool>,
    bootstrap_thread: Option<RaiiThreadJoiner>,
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
        let (upnp_addr_tx, _upnp_addr_rx) = mpsc::channel();
        let mapper = Arc::new(try!(::hole_punching::HolePunchServer::start(upnp_addr_tx)));

        // TODO (canndrew): Handle HolePunchServer external address updates by notifying all
        // connected clients.
        // let upnp_updater_handle = RaiiThreadJoiner::new(thread!("upnp j
        let connection_map = Arc::new(ConnectionMap::new(event_sender.clone()));

        let service = Service {
            beacon_guid_and_port: None,
            config: config,
            bootstrap_peers: None,
            bootstrap_handler: try!(BootstrapHandler::new()),
            acceptors: Vec::new(),
            mapper: mapper,
            next_punch_sequence: SequenceNumber::new(::rand::random()),
            event_sender: event_sender,
            connection_map: connection_map,
            is_bootstrapping: Arc::new(AtomicBool::new(false)),
            bootstrap_thread: None,
        };

        Ok(service)
    }

    fn get_local_endpoints(&self) -> Vec<Endpoint> {
        self.acceptors
            .iter()
            .map(|a| Endpoint::from_socket_addr(Protocol::Tcp, a.local_address()))
            .collect()
    }

    /// Sends a message over a specified connection.
    pub fn send(&self, connection: Connection, bytes: Vec<u8>) {
        self.connection_map.send(connection, bytes)
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
    pub fn start_accepting(&mut self, port: u16) -> Result<Endpoint, Error> {
        let listener = try!(TcpListener::bind(("0.0.0.0", port)));
        let accept_addr = try!(listener.local_addr());

        let hole_punch_server = self.mapper.clone();
        let acceptor = try!(Acceptor::new(listener,
                                          hole_punch_server,
                                          self.connection_map.clone(),
                                          self.event_sender.clone()));
        self.acceptors.push(acceptor);

        // FIXME: Instead of hardcoded wrapping in loopback V4, the
        // acceptor should tell us the address it is accepting on.
        Ok(Endpoint::from_socket_addr(Protocol::Tcp, SocketAddr(accept_addr)))
    }

    fn populate_bootstrap_contacts(&mut self,
                                   config: &Config,
                                   beacon_port: Option<u16>,
                                   own_beacon_guid_and_port: &Option<([u8; 16], u16)>)
                                   -> Vec<Endpoint> {
        let cached_contacts = self.bootstrap_handler.read_file().unwrap_or(vec![]);

        let beacon_guid = own_beacon_guid_and_port.map(|(guid, _)| guid);

        let beacon_discovery = match beacon_port {
            Some(port) => Self::seek_peers(beacon_guid, port),
            None => vec![],
        };

        let mut combined_contacts = beacon_discovery.into_iter()
                                                    .chain(config.hard_coded_contacts
                                                                 .iter()
                                                                 .cloned())
                                                    .chain(cached_contacts.into_iter())
                                                    .unique()
                                                    .collect::<Vec<_>>();

        // remove own endpoints
        let own_listening_endpoint = self.get_known_external_endpoints();
        combined_contacts.retain(|c| !own_listening_endpoint.contains(&c));
        combined_contacts
    }

    fn seek_peers(beacon_guid: Option<[u8; 16]>, beacon_port: u16) -> Vec<Endpoint> {
        match beacon::seek_peers(beacon_port, beacon_guid) {
            Ok(peers) => {
                peers.into_iter().map(|a| Endpoint::from_socket_addr(Protocol::Tcp, a)).collect()
            }
            Err(_) => Vec::new(),
        }
    }

    fn start_broadcast_acceptor(&mut self, beacon_port: u16) -> io::Result<u16> {
        let acceptor = try!(beacon::BroadcastAcceptor::new(beacon_port));
        let b_port = acceptor.beacon_port();

        // Right now we expect this function to succeed only once.
        assert!(self.beacon_guid_and_port.is_none());
        self.beacon_guid_and_port = Some((acceptor.beacon_guid(), b_port));

        let connection_map = self.connection_map.clone();
        let event_sender = self.event_sender.clone();
        let thread_result = Self::new_thread("beacon acceptor", move || {
            while let Ok((h, t)) = acceptor.accept() {
                let c = t.connection_id.clone();
                let our_external_endpoint = Endpoint::from_socket_addr(*t.connection_id
                                                                         .peer_endpoint()
                                                                         .protocol(),
                                                                       SocketAddr(*h.remote_addr));
                let _ = event_sender.send(Event::OnBootstrapAccept(our_external_endpoint, c));
                let _ = connection_map.register_connection(h, t);
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

        let mut contacts = self.populate_bootstrap_contacts(&config,
                                                            beacon_port,
                                                            &beacon_guid_and_port);
        let mapper_cloned = self.mapper.clone();
        contacts.retain(|endpoint| !blist.contains(&endpoint));
        self.bootstrap_off_list(token, contacts.clone(), mapper_cloned)
    }

    /// Remove endpoint from the bootstrap cache.
    pub fn remove_bootstrap_contact(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        // TODO (canndrew): This should probably happen asynchronously
        // because it uses (possibly slow) filesystem operations.
        self.bootstrap_handler.update_contacts(vec![], vec![endpoint])
    }

    // This should be called before destroying an instance of a Service to allow the
    // listener threads to join.  Once called, the Service should be destroyed.
    fn stop(&mut self) {
        if let Some(beacon_guid_and_port) = self.beacon_guid_and_port.take() {
            beacon::BroadcastAcceptor::stop(&beacon_guid_and_port);
        }

    }

    // TODO (canndrew): do we even need this method?
    /// Check whether we're connected to an endpoint.
    pub fn is_connected_to(&self, endpoint: &Endpoint) -> bool {
        self.connection_map.is_connected_to(endpoint)
    }

    /// Get the hole punch servers addresses of nodes that we're connected to ordered by how likely
    /// they are to be on a seperate network.
    pub fn get_ordered_helping_nodes(&self) -> Vec<SocketAddr> {
        self.connection_map.get_ordered_helping_nodes()
    }

    /// Bootstrap to the network using the provided list of peers.
    pub fn bootstrap_off_list(&mut self,
                              token: u32,
                              bootstrap_list: Vec<Endpoint>,
                              hole_punch_server: Arc<HolePunchServer>) {
        if self.is_bootstrapping.compare_and_swap(false, true, Ordering::SeqCst) {
            let _ = unwrap_option!(self.bootstrap_peers.as_ref(),
                                   "bootstrap_peers cannot be None!")
                        .send(bootstrap_list);
            return;
        }

        let (tx, rx) = mpsc::channel();
        let _ = tx.send(bootstrap_list);
        self.bootstrap_peers = Some(tx);

        let is_bootstrapping = self.is_bootstrapping.clone();
        let bootstrap_thread = self.bootstrap_thread.take();
        if let Some(handle) = bootstrap_thread {
            drop(handle)
        };

        let connection_map = self.connection_map.clone();
        let event_sender = self.event_sender.clone();

        let handle = RaiiThreadJoiner::new(thread!("bootstrap thread", move || {
            for endpoint in rx.iter().flat_map(|v| v.into_iter()) {
                // Bootstrapping got cancelled.
                if !is_bootstrapping.load(Ordering::SeqCst) {
                    return;
                }
                if connection_map.is_connected_to(&endpoint) {
                    continue;
                }

                let mapper_port = hole_punch_server.listening_addr().port();
                let external_addr = hole_punch_server.external_address();

                let h = Handshake {
                    mapper_port: Some(mapper_port),
                    external_addr: external_addr,
                    remote_addr: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
                };
                let connect_result = transport::connect(endpoint)
                                         .and_then(|t| transport::exchange_handshakes(h, t));
                if !is_bootstrapping.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok((handshake, trans)) = connect_result {
                    let c = trans.connection_id.clone();
                    let our_external_endpoint =
                        Endpoint::from_socket_addr(*trans.connection_id
                                                         .peer_endpoint()
                                                         .protocol(),
                                                   SocketAddr(*handshake.remote_addr));
                    let _ = event_sender.send(Event::OnBootstrapConnect(Ok((our_external_endpoint,
                                                                            c)),
                                                                        token));
                    let _ = connection_map.register_connection(handshake, trans);
                }
            }
            is_bootstrapping.store(false, Ordering::SeqCst);
            let _ = event_sender.send(Event::BootstrapFinished);
        }));
        self.bootstrap_thread = Some(handle);
    }

    /// Stop the bootstraping procedure
    pub fn stop_bootstrap(&mut self) {
        self.is_bootstrapping.store(false, Ordering::SeqCst);
    }

    // Accept a connection on the provided TcpListener and perform a handshake on it.
    // pub fn accept(handshake: Handshake,
    // acceptor: &TcpListener)
    // -> io::Result<(Handshake, Transport)> {
    // transport::exchange_handshakes(handshake, try!(transport::accept(acceptor)))
    // }
    //

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
    /// On success `Event::OnConnect` with connected `Endpoint` will
    /// be sent to the event channel. On failure, nothing is reported. Failed
    /// attempts are not notified back up to the caller. If the caller wants to
    /// know of a failed attempt, it must maintain a record of the attempt
    /// itself which times out if a corresponding
    /// `Event::OnConnect` isn't received. See also [Process for
    /// Connecting]
    /// (https://github.com/maidsafe/crust/blob/master/docs/connect.md) for
    /// details on handling of connect in different protocols.
    pub fn connect(&self,
                   our_contact_info: OurContactInfo,
                   their_contact_info: TheirContactInfo,
                   token: u32) {
        let mapper_external_addr = self.mapper.external_address();
        let mapper_internal_port = self.mapper.listening_addr().port();

        let handshake = Handshake {
            mapper_port: Some(mapper_internal_port),
            external_addr: mapper_external_addr,
            remote_addr: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
        };

        let event_sender = self.event_sender.clone();
        let connection_map = self.connection_map.clone();

        if our_contact_info.secret != their_contact_info.secret {
            let err = io::Error::new(io::ErrorKind::Other,
                                     "Cannot connect. our_contact_info and their_contact_info \
                                      are not associated with the same connection.");
            let _ = event_sender.send(Event::OnConnect(Err(err), token));
            return;
        }

        let rendezvous_addr = match their_contact_info.rendezvous_addrs.get(0) {
            Some(addr) => addr.clone(),
            None => {
                let err = io::Error::new(io::ErrorKind::Other,
                                         "No rendezvous address supplied. Direct connections not \
                                          yet supported.");
                let _ = event_sender.send(Event::OnConnect(Err(err), token));
                return;
            }
        };

        let _ = Self::new_thread("rendezvous connect", move || {
            let (udp_socket, result_addr) =
                ::hole_punching::blocking_udp_punch_hole(our_contact_info.socket,
                                                         our_contact_info.secret,
                                                         rendezvous_addr);
            let public_endpoint = match result_addr {
                Ok(addr) => addr,
                Err(e) => {
                    let _ = event_sender.send(Event::OnConnect(Err(e), token));
                    return;
                }
            };

            let peer_endpoint = Endpoint::from_socket_addr(Protocol::Utp, public_endpoint);
            let res = transport::rendezvous_connect(udp_socket, peer_endpoint);
            let res = res.and_then(move |t| transport::exchange_handshakes(handshake, t));

            let (his_handshake, transport) = match res {
                Ok((h, t)) => (h, t),
                Err(e) => {
                    let _ = event_sender.send(Event::OnConnect(Err(e), token));
                    return ();
                }
            };

            let c = transport.connection_id.clone();
            let our_external_endpoint =
                Endpoint::from_socket_addr(*transport.connection_id
                                                     .peer_endpoint()
                                                     .protocol(),
                                           SocketAddr(*his_handshake.remote_addr));
            let _ = event_sender.send(Event::OnConnect(Ok((our_external_endpoint, c)), token));
            let _ = connection_map.register_connection(his_handshake, transport);
        });
    }

    /// Closes a connection.
    pub fn drop_node(&self, connection: Connection) {
        self.connection_map.unregister_connection(connection);
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

    /// Get already known external endpoints without any upnp mapping
    pub fn get_known_external_endpoints(&self) -> Vec<Endpoint> {
        let mut ret = Vec::new();
        for acceptor in &self.acceptors {
            ret.extend(acceptor.mapped_addresses());
        }
        ret.iter().map(|a| Endpoint::from_socket_addr(Protocol::Tcp, *a)).collect()
    }

    // pub fn bootstrap_off_list(&mut self, token: u32, mut bootstrap_list: Vec<Endpoint>) {
    // match self.bootstrap_thread {
    // Some(_) => (),
    // None => {
    // let joiner = RaiiThreadJoiner::new(thread!("bootstrap", move || {
    // for peer_endpoint in bootstrap_list {
    // if
    // }
    //
    // }));
    // self.bootstrap_thread = Some(joiner);
    // }
    // }
    // }
    //

    /// Initiates uPnP port mapping of the currently used accepting endpoints.
    /// On success ExternalEndpoint event is generated containg our external
    /// endpoints.
    pub fn get_external_endpoints(&self) {
        let internal_eps = self.get_local_endpoints();

        type T = (SocketAddrV4, Endpoint);

        struct Async {
            remaining: usize,
            results: Vec<Endpoint>,
        }

        let async = Arc::new(Mutex::new(Async {
            remaining: internal_eps.len(),
            results: Vec::new(),
        }));

        for internal_ep in internal_eps {
            let async = async.clone();
            let event_sender = self.event_sender.clone();

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
    }

    // TODO (canndrew): Remove this (replace with thread! macro)
    fn new_thread<F, T>(name: &str, f: F) -> io::Result<JoinHandle<T>>
        where F: FnOnce() -> T,
              F: Send + 'static,
              T: Send + 'static
    {
        thread::Builder::new()
            .name("Service::".to_owned() + name)
            .spawn(f)
    }

    /// Lookup a mapped udp socket based on result_token
    pub fn prepare_contact_info(&mut self, result_token: u32) {
        use hole_punching::blocking_get_mapped_udp_socket;

        let seq_id = self.next_punch_sequence.number();
        self.next_punch_sequence.increment();

        let helping_nodes = self.get_ordered_helping_nodes();
        let event_sender = self.event_sender.clone();

        let static_addrs = self.get_known_external_endpoints();

        let _result_handle = Self::new_thread("map_udp", move || {
            let result = blocking_get_mapped_udp_socket(seq_id, helping_nodes);

            let res = match result {
                // TODO (peterj) use _rest
                Ok((socket, opt_mapped_addr, _rest)) => {
                    let addrs = opt_mapped_addr.into_iter().collect();
                    Ok(OurContactInfo {
                        socket: socket,
                        secret: Some(rand::random()),
                        static_addrs: static_addrs,
                        rendezvous_addrs: addrs,
                    })
                }
                Err(what) => Err(what),
            };

            let _ = event_sender.send(Event::ContactInfoPrepared(ContactInfoResult {
                result_token: result_token,
                result: res,
            }));
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
    use std::net::{UdpSocket, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::mpsc::{Sender, Receiver, channel};
    use std::sync::Arc;
    use std::thread;
    use std::thread::spawn;
    use std::net;
    use rand;
    use rustc_serialize::{Decodable, Encodable};
    use cbor::{Decoder, Encoder};
    use connection::Connection;
    use endpoint::{Protocol, Endpoint};
    use config_handler::write_config_file;
    use event::Event;
    use hole_punching::HolePunchServer;
    use bootstrap_handler::BootstrapHandler;
    use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
    use socket_addr::SocketAddr;
    use maidsafe_utilities::thread::RaiiThreadJoiner;
    use error::Error;
    use event::{OurContactInfo, TheirContactInfo};

    type CategoryRx = ::std::sync::mpsc::Receiver<MaidSafeEventCategory>;

    fn encode<T>(value: &T) -> Vec<u8>
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

    fn filter_ok<T>(vec: Vec<Result<T, Error>>) -> Vec<T> {
        vec.into_iter().filter_map(|a| a.ok()).collect()
    }

    fn try_recv_with_timeout<T>(receiver: &Receiver<T>,
                                timeout: ::std::time::Duration)
                                -> Option<T> {
        use std::sync::mpsc::TryRecvError;

        let interval = ::std::time::Duration::from_millis(100);
        let mut elapsed = ::std::time::Duration::from_millis(0);

        loop {
            match receiver.try_recv() {
                Ok(value) => return Some(value),
                Err(TryRecvError::Disconnected) => break,
                _ => (),
            }

            thread::sleep(interval);
            elapsed = elapsed + interval;

            if elapsed > timeout {
                break;
            }
        }

        None
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
            Ok(Event::OnBootstrapConnect(conn, _)) => {
                debug!("OnBootstrapConnect {:?}", conn);
            }
            Ok(Event::OnBootstrapAccept(addr, ep)) => {
                debug!("OnBootstrapAccept {:?} {:?}", addr, ep);
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
    //                     Ok(Event::OnBootstrapConnect(Ok((_, conn)), _)) => {
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
                                    Event::OnBootstrapConnect(Ok((_, other_ep)), _) => {
                                        cm.send(other_ep.clone(),
                                                encode(&"hello world".to_owned()));
                                    }
                                    Event::OnBootstrapAccept(_, other_ep) => {
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

        let (tx, _rx) = channel();
        let hole_punch_server = Arc::new(unwrap_result!(HolePunchServer::start(tx)));

        cm2.bootstrap_off_list(0, cm1_eps, hole_punch_server.clone());
        cm1.bootstrap_off_list(1, cm2_eps, hole_punch_server.clone());

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
                                        Event::OnConnect(Ok((_, other_ep)), _) => {
                                            cm.send(other_ep.clone(),
                                                    encode(&"hello world".to_owned()));
                                        }
                                        Event::OnConnect(Err(error), _) => {
                                            panic!("Cannot establish rendezvous connection: {:?}",
                                                   error);
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

        let secret = Some(rand::random());
        let peer1_our_ci = OurContactInfo {
            socket: peer1_udp_socket,
            secret: secret,
            static_addrs: Vec::new(),
            rendezvous_addrs: vec![peer1_addr],
        };
        let peer2_our_ci = OurContactInfo {
            socket: peer2_udp_socket,
            secret: secret,
            static_addrs: Vec::new(),
            rendezvous_addrs: vec![peer2_addr],
        };
        let peer1_their_ci = TheirContactInfo {
            secret: secret,
            static_addrs: Vec::new(),
            rendezvous_addrs: vec![peer2_addr],
        };
        let peer2_their_ci = TheirContactInfo {
            secret: secret,
            static_addrs: Vec::new(),
            rendezvous_addrs: vec![peer1_addr],
        };

        cm2.connect(peer1_our_ci, peer1_their_ci, 0);
        cm1.connect(peer2_our_ci, peer2_their_ci, 0);

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

    #[test]
    fn lost_rendezvous_connection() {
        let (category_tx, category_rx) = channel();
        let (event_tx, event_rx) = channel();

        let event_sender0 = MaidSafeObserver::new(event_tx.clone(),
                                                  MaidSafeEventCategory::CrustEvent,
                                                  category_tx.clone());

        let event_sender1 = MaidSafeObserver::new(event_tx,
                                                  MaidSafeEventCategory::CrustEvent,
                                                  category_tx);

        let service0 = Service::new(event_sender0).unwrap();
        let service1 = Service::new(event_sender1).unwrap();

        let socket0 = UdpSocket::bind("0.0.0.0:0").unwrap();
        let socket1 = UdpSocket::bind("0.0.0.0:0").unwrap();

        let loopback = ::ip::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let port0 = socket0.local_addr().unwrap().port();

        let port1 = socket1.local_addr().unwrap().port();

        let token0 = 0;
        let token1 = 1;

        let secret = Some(rand::random());
        let our_ci0 = OurContactInfo {
            socket: socket0,
            secret: secret,
            static_addrs: vec![],
            rendezvous_addrs: vec![SocketAddr::new(loopback, port0)],
        };
        let our_ci1 = OurContactInfo {
            socket: socket1,
            secret: secret,
            static_addrs: vec![],
            rendezvous_addrs: vec![SocketAddr::new(loopback, port1)],
        };

        let their_ci0 = TheirContactInfo {
            secret: secret,
            static_addrs: vec![],
            rendezvous_addrs: vec![SocketAddr::new(loopback, port1)],
        };
        let their_ci1 = TheirContactInfo {
            secret: secret,
            static_addrs: vec![],
            rendezvous_addrs: vec![SocketAddr::new(loopback, port0)],
        };

        service0.connect(our_ci0, their_ci0, token0);
        service1.connect(our_ci1, their_ci1, token1);

        let _joiner = RaiiThreadJoiner::new(spawn(move || {
            let mut service1 = Some(service1);

            let mut peer0_connection = None;
            let mut peer1_connection = None;

            let mut peer0_received_lost_connection = false;

            let timeout = ::std::time::Duration::from_secs(10);

            while let Some(category) = try_recv_with_timeout(&category_rx, timeout) {
                match category {
                    MaidSafeEventCategory::CrustEvent => {
                        match event_rx.try_recv() {
                            Ok(Event::OnConnect(Ok((_, conn)), token)) => {
                                match token {
                                    0 => peer0_connection = Some(conn),
                                    1 => peer1_connection = Some(conn),
                                    _ => unreachable!("Token {} should not have been sent", token),
                                }

                                if peer0_connection.is_some() && peer1_connection.is_some() {
                                    // Drop this service to cause lost connection.
                                    let _ = service1.take();
                                }
                            }

                            Ok(Event::LostConnection(conn)) => {
                                if Some(conn) == peer0_connection {
                                    peer0_received_lost_connection = true;
                                    break;
                                }
                            }

                            event => println!("event: {:?}", event),
                        }
                    }

                    _ => unreachable!("This category should not have been fired - {:?}", category),
                }
            }

            assert!(peer0_received_lost_connection);
        }));
    }

    #[test]
    fn lost_tcp_connection() {
        let (category_tx, category_rx) = channel();
        let (event_tx, event_rx) = channel();

        let event_sender0 = MaidSafeObserver::new(event_tx.clone(),
                                                  MaidSafeEventCategory::CrustEvent,
                                                  category_tx.clone());

        let event_sender1 = MaidSafeObserver::new(event_tx,
                                                  MaidSafeEventCategory::CrustEvent,
                                                  category_tx);

        let mut service0 = Service::new(event_sender0).unwrap();
        let mut service1 = Service::new(event_sender1).unwrap();

        let endpoint0 = service0.start_accepting(0)
                                .unwrap()
                                .port();
        let endpoint0 = Endpoint::new(Protocol::Tcp,
                                      ::ip::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                                      endpoint0);


        let (tx, _rx) = channel();
        let hole_punch_server = Arc::new(unwrap_result!(HolePunchServer::start(tx)));

        service1.bootstrap_off_list(0, vec![endpoint0], hole_punch_server);

        let _joiner = RaiiThreadJoiner::new(spawn(move || {
            let mut peer0_connection = None;
            let mut peer0_received_lost_connection = false;

            let mut service1 = Some(service1);

            let timeout = ::std::time::Duration::from_secs(10);

            while let Some(category) = try_recv_with_timeout(&category_rx, timeout) {
                match category {
                    MaidSafeEventCategory::CrustEvent => {
                        match event_rx.try_recv() {
                            Ok(Event::OnBootstrapAccept(_, conn)) => {
                                peer0_connection = Some(conn);
                            }

                            Ok(Event::OnBootstrapConnect(Ok(_), _)) => {
                                // Drop this service.
                                let _ = service1.take();
                            }

                            Ok(Event::LostConnection(conn)) => {
                                if Some(conn) == peer0_connection {
                                    peer0_received_lost_connection = true;
                                    break;
                                }
                            }

                            _ => (),
                        }
                    }

                    _ => unreachable!("This category should not have been fired - {:?}", category),
                }
            }

            assert!(peer0_received_lost_connection);
        }));
    }

    #[test]
    fn network() {
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
                                    Event::OnBootstrapConnect(Ok((_, connection)), _) => {
                                        stats.connect_count += 1;
                                        self.send_data_to(connection);
                                    }
                                    Event::OnBootstrapAccept(_, connection) => {
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
                                     .map(|node| node.service.start_accepting(0).unwrap())
                                     .map(|ep| ep)
                                     .collect::<::std::collections::VecDeque<_>>();

        let (tx, _rx) = channel();
        let hole_punch_server = Arc::new(unwrap_result!(HolePunchServer::start(tx)));

        for mut node in nodes {
            assert!(listening_eps.pop_front().is_some());

            for ep in &listening_eps {
                node.service.bootstrap_off_list(0, vec![ep.clone()], hole_punch_server.clone());
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
    fn connection_manager_start() {
        unwrap_result!(BootstrapHandler::cleanup());

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
        let mut cm = unwrap_result!(Service::new(event_sender));

        let cm_listen_ep = unwrap_result!(cm.start_accepting(0));

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

        let t = spawn(move || {
            let _temp_config = make_temp_config();
            let (category_tx, category_rx) = channel();
            let (cm_aux_tx, cm_aux_rx) = channel();
            let event_sender = ::maidsafe_utilities::event_sender::MaidSafeObserver::new(cm_aux_tx,
                                                                                         cloned_crust_event_category,
                                                                                         category_tx);
            let mut cm_aux = unwrap_result!(Service::new(event_sender));
            // setting the listening port to be greater than 4455 will make the test hanging
            // changing this to cm_beacon_addr will make the test hanging
            let (tx, _rx) = channel();
            let hole_punch_server = Arc::new(unwrap_result!(HolePunchServer::start(tx)));

            cm_aux.bootstrap_off_list(0, vec![cm_listen_ep], hole_punch_server);

            for it in category_rx.iter() {
                match it {
                    ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent => {
                        if let Ok(event) = cm_aux_rx.try_recv() {
                            if let Event::OnBootstrapConnect(_, _) = event {
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
        let _ = t.join();
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
