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

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, mpsc, Mutex, Weak};
use std::thread;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use beacon;
use bootstrap_handler::{BootstrapHandler, parse_contacts};
use config_handler::{Config, read_config_file};
use getifaddrs::{getifaddrs, filter_loopback};
use transport;
use transport::{Endpoint, Port};

use asynchronous::{Deferred,ControlFlow};
use itertools::Itertools;

use igd;

/// Type used to represent serialised data in a message.
pub type Bytes = Vec<u8>;

type WeakState = Weak<Mutex<State>>;

/// A structure representing a connection manager
///
/// This abstraction has a hidden dependency on per-executable config
/// file. Refer to
/// https://github.com/maidsafe/crust/blob/master/docs/configuration_path.md for
/// more information.
pub struct ConnectionManager {
    state: Arc<Mutex<State>>,
    beacon_guid_and_port: Option<(beacon::GUID, u16)>,
    config: Config,
    own_endpoints: Vec<(Endpoint, Arc<Mutex<Option<Endpoint>>>)>,
}

/// Enum representing different events that will be sent over the asynchronous channel to the user
/// of this module.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Event {
    /// Invoked when a new message is received.  Passes the peer's endpoint and the message.
    NewMessage(Endpoint, Bytes),
    /// Invoked when a new connection to a peer is established.  Passes the peer's endpoint.
    NewConnection(Endpoint),
    /// Invoked when a connection to a peer is lost.  Passes the peer's endpoint.
    LostConnection(Endpoint),
    /// Invoked when a new bootstrap connection to a peer is established.  Passes the peer's endpoint.
    NewBootstrapConnection(Endpoint),
}

struct Connection {
    writer_channel: mpsc::Sender<Bytes>,
}

struct State {
    event_pipe: mpsc::Sender<Event>,
    connections: HashMap<Endpoint, Connection>,
    listening_ports: HashSet<Port>,
    bootstrap_handler: Option<BootstrapHandler>,
    stop_called: bool,
    bootstrap_count: (usize, usize), // (current, max)
}

fn map_external_port(port: &Port)
                     -> Vec<(Endpoint, Arc<Mutex<Option<Endpoint>>>)> {
    let (protocol, port_number) = match *port {
        Port::Tcp(port) => (igd::PortMappingProtocol::TCP, port),
        Port::Utp(port) => (igd::PortMappingProtocol::UDP, port),
    };
    // Removing loopback address
    filter_loopback(getifaddrs()).into_iter().filter_map(|e| match e.addr {
        IpAddr::V4(a) => {
            let addr = SocketAddrV4::new(a, port_number);
            let ext = Arc::new(Mutex::new(None));
            let ext2 = ext.clone();
            let port2 = port.clone();

            let _ = thread::spawn(move || {
                match igd::search_gateway_from(addr.ip().clone()) {
                    Ok(gateway) => {
                        let _ = gateway.add_port(protocol, port_number,
                                                 addr.clone(), 0, "crust");

                        match gateway.get_external_ip() {
                            Ok(ip) => {
                                let endpoint = SocketAddr
                                    ::V4(SocketAddrV4::new(ip, port_number));
                                let mut data = ext2.lock().unwrap();
                                *data = Some(match port2 {
                                    Port::Tcp(_) => Endpoint::Tcp(endpoint),
                                    Port::Utp(_) => Endpoint::Utp(endpoint),
                                })
                            },
                            Err(_) => (),
                        }
                    },
                    Err(_) => (),
                }
            });

            let addr = SocketAddr::V4(addr);
            Some((match *port {
                Port::Tcp(_) => Endpoint::Tcp(addr),
                Port::Utp(_) => Endpoint::Utp(addr),
            }, ext))
        },
        _ => None,
    }).collect::<Vec<_>>()
}

impl ConnectionManager {
    /// Constructs a connection manager. User needs to create an asynchronous channel, and provide
    /// the sender half to this method. Receiver will receive all `Event`s from this library.
    pub fn new(event_pipe: mpsc::Sender<Event>) -> io::Result<ConnectionManager> {
        let config = read_config_file().unwrap_or_else(|e| {
            debug!("Crust failed to read config file; Error: {:?};", e);
            ::config_handler::create_default_config_file();
            let default = Config::make_default();
            debug!("Using default beacon_port {:?} and default bootstrapping methods enabled",
                default.beacon_port);
            default
        });

        let state = Arc::new(Mutex::new(State{ event_pipe: event_pipe,
                                               connections: HashMap::new(),
                                               listening_ports: HashSet::new(),
                                               bootstrap_handler: None,
                                               stop_called: false,
                                               bootstrap_count: (0,0),
                                             }));

        let tcp_listening_port = config.tcp_listening_port.clone();
        let utp_listening_port = config.utp_listening_port.clone();

        let mut cm = ConnectionManager { state                : state,
                                         beacon_guid_and_port : None,
                                         config               : config,
                                         own_endpoints        : Vec::new()
                                       };

        let _ = cm.start_broadcast_acceptor();

        if let Some(port) = tcp_listening_port {
            let _ = try!(cm.start_accepting(Port::Tcp(port)));
        }

        if let Some(port) = utp_listening_port {
            let _ = try!(cm.start_accepting(Port::Utp(port)));
        }

        Ok(cm)
    }

    /// Starts listening on all supported protocols. Ports in _hint_ are tried
    /// first.  On failure to listen on none of _hint_ an OS randomly chosen
    /// port will be used for each supported protocol. The actual port used will
    /// be returned on which it started listening for each protocol.
    pub fn start_accepting(&mut self, port: Port) -> io::Result<Port> {
        match self.beacon_guid_and_port {
            Some(_) => {
                let listening_port = try!(self.listen(port));

                let contacts = filter_loopback(getifaddrs()).into_iter()
                    .map(|ip| {
                        ::contact::Contact {
                            endpoint: Endpoint::new(ip.addr.clone(), listening_port)
                        }
                    })
                    .collect::<Vec<_>>();

                let weak_state = Arc::downgrade(&self.state);
                // TODO: provide a prune list as the second argument to update_contacts
                update_bootstrap_contacts(weak_state, contacts, ::contact::Contacts::new());
                Ok(listening_port)
            },
            None => {
                self.listen(port)
            }
        }
    }

    fn start_broadcast_acceptor(&mut self) -> io::Result<()> {
        let acceptor = try!(beacon::BroadcastAcceptor::new(self.config.beacon_port));

        // Right now we only expect this function to succeed once.
        assert!(self.beacon_guid_and_port.is_none());
        self.beacon_guid_and_port = Some((acceptor.beacon_guid(), acceptor.beacon_port()));

        // If it succeeds we "take ownership" of the `BootstrapHandler` in order to avoid the
        // process-safety issues described in the docs of `FileHandler`.
        let _ = lock_mut_state(&mut Arc::downgrade(&self.state), |state: &mut State| {
            assert!(state.bootstrap_handler.is_none());
            state.bootstrap_handler = Some(BootstrapHandler::new());
            Ok(())
        });

        let weak_state = Arc::downgrade(&self.state);
        let thread_result = thread::Builder::new()
                            .name("ConnectionManager beacon acceptor".to_string())
                            .spawn(move || {
            while let Ok(transport) = acceptor.accept() {
                Self::respond_to_broadcast(weak_state.clone(), transport);
            }
        });

        match thread_result {
            Ok(_) => Ok(()),
            Err(what) => {
                self.beacon_guid_and_port = None;
                Err(what)
            }
        }
    }

    fn respond_to_broadcast(mut weak_state: Weak<Mutex<State>>,
                            mut transport: ::transport::Transport) {
        let _ = lock_mut_state(&mut weak_state, |state: &mut State| {
            if let Some(ref mut handler) = state.bootstrap_handler {
                if let Ok(serialised_contacts) = handler.serialise_contacts() {
                    let _ = transport.sender.send(&serialised_contacts);
                }
            }
            Ok(())
        });
    }

    fn get_listening_endpoint(ws: Weak<Mutex<State>>) -> io::Result<(Vec<Endpoint>)> {
        let listening_ports = try!(lock_state(&ws, |s| {
            let buf: Vec<Port> = s.listening_ports.iter().map(|s| s.clone()).collect();
            Ok(buf)
        }));

        let mut endpoints = Vec::<Endpoint>::new();
        for port in listening_ports {
            for ifaddr in filter_loopback(getifaddrs()) {
                endpoints.push(Endpoint::new(ifaddr.addr, port));
            }
        }
        Ok(endpoints)
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
    /// Maximum of `max_successful_bootstrap_connection` bootstrap connections will be made and further connection
    /// attempts will stop.
    /// It will reiterate the list of all endpoints until it gets at least one connection.
    pub fn bootstrap(&mut self, max_successful_bootstrap_connection: usize) {
        // Disconnect existing connections
        let mut ws = Arc::downgrade(&self.state);
        let _ = lock_mut_state(&mut ws, |s: &mut State| {
            let _ = s.connections.clear();
            s.bootstrap_count = (0, max_successful_bootstrap_connection.clone());
            Ok(())
        });

        let ws = Arc::downgrade(&self.state);
        let bs_file_lock = self.beacon_guid_and_port.is_some();
        let config = self.config.clone();
        let beacon_guid_and_port = self.beacon_guid_and_port.clone();
        let _ = thread::Builder::new().name("ConnectionManager bootstrap loop".to_string()).spawn(move || {
            loop {
                let contacts = Self::populate_bootstrap_contacts(&config,
                                                                 &beacon_guid_and_port,
                                                                 ws.clone());
                match bootstrap_off_list(ws.clone(), contacts.clone(), bs_file_lock,
                                         max_successful_bootstrap_connection) {
                    Ok(_) => {
                        debug!("Got at least one bootstrap connection. Breaking bootstrap loop.");
                        break;
                    },
                    Err(_) => {
                        // debug!("Failed to get at least one bootstrap connection. continuing bootstrap loop");
                    }
                }
                // breaking the loop if stop called
                let weak_state_copy = ws.clone();
                let mut stop_called = false;
                {
                    let _ = lock_mut_state(&weak_state_copy, |state: &mut State| {
                        stop_called = state.stop_called;
                        Ok(())
                    });
                }
                if stop_called {
                    break
                }
            }
        });
    }

    /// This should be called before destroying an instance of a ConnectionManager to allow the
    /// listener threads to join.  Once called, the ConnectionManager should be destroyed.
    pub fn stop(&mut self) {
        if let Some(beacon_guid_and_port) = self.beacon_guid_and_port {
            beacon::BroadcastAcceptor::stop(&beacon_guid_and_port);
            self.beacon_guid_and_port = None;
        }
        let mut listening_ports = Vec::<Port>::new();
        let weak_state = Arc::downgrade(&self.state);
        {
            let _ = lock_mut_state(&weak_state, |state: &mut State| {
                for itr in &state.listening_ports {
                    listening_ports.push(itr.clone());
                }
                state.listening_ports.clear();
                state.stop_called = true;
                Ok(())
            });
        }
        // debug!("connection_manager::stop There are {} TCP ports being listened on", listening_ports.len());
        for port in listening_ports {
            let ip_addr = IpAddr::V4(Ipv4Addr::new(127,0,0,1));
            let _ = transport::connect(Endpoint::new(ip_addr, port));
        }
    }

    /// Opens a connection to a remote peer. `endpoints` is a vector of addresses of the remote
    /// peer. All the endpoints will be tried. As soon as a connection is established, it will drop
    /// all other ongoing attempts. On success `Event::NewConnection` with connected `Endpoint` will
    /// be sent to the event channel. On failure, nothing is reported.
    /// Failed attempts are not notified back up to the caller. If the caller wants to know of a
    /// failed attempt, it must maintain a record of the attempt itself which times out if a
    /// corresponding Event::NewConnection isn't received
    /// For details on handling of connect in different protocol refer
    /// https://github.com/dirvine/crust/blob/master/docs/connect.md
    pub fn connect(&self, endpoints: Vec<Endpoint>) {
        let ws = Arc::downgrade(&self.state);
        {
            let result = lock_mut_state(&ws, |s: &mut State| {
                for endpoint in &endpoints {
                    if s.connections.contains_key(&endpoint) {
                        return Err(io::Error::new(io::ErrorKind::AlreadyExists,
                                                  "Already connected"))
                    }
                }
                Ok(())
            });
            if result.is_err() {
                return
            }
        }
        let is_broadcast_acceptor = self.beacon_guid_and_port.is_some();
        let _ = thread::Builder::new().name("ConnectionManager connect".to_string()).spawn(move || {
            for endpoint in &endpoints {
                let ws = ws.clone();
                let result = transport::connect(endpoint.clone())
                              .and_then(|trans| handle_connect(ws, trans,
                                        is_broadcast_acceptor, false));
                if result.is_ok() { return; }
            }
        });
    }

    /// Sends a message to specified address (endpoint). Returns Ok(()) if the sending might
    /// succeed, and returns an Err if the address is not connected. Return value of Ok does not
    /// mean that the data will be received. It is possible for the corresponding connection to hang
    /// up immediately after this function returns Ok.
    pub fn send(&self, endpoint: Endpoint, message: Bytes) -> io::Result<()> {
        let ws = Arc::downgrade(&self.state);

        let writer_channel = try!(lock_state(&ws, |s| {
            match s.connections.get(&endpoint) {
                Some(c) =>  Ok(c.writer_channel.clone()),
                None => Err(io::Error::new(io::ErrorKind::NotConnected, "?"))
            }
        }));

        let send_result = writer_channel.send(message);
        let cant_send = io::Error::new(io::ErrorKind::BrokenPipe, "?");
        send_result.map_err(|_|cant_send)
    }

    /// Closes connection with the specified endpoint.
    pub fn drop_node(&self, endpoint: Endpoint) {
        let mut ws = Arc::downgrade(&self.state);
        let _ = lock_mut_state(&mut ws, |s: &mut State| {
            let _ = s.connections.remove(&endpoint);
            Ok(())
        });
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

    fn seek_peers(beacon_guid: Option<[u8; 16]>, beacon_port: u16) -> Vec<Endpoint> {
        // Retrieve list of peers' TCP listeners who are on same subnet as us
        let peer_addresses = match beacon::seek_peers(beacon_port, beacon_guid) {
            Ok(peers) => peers,
            Err(_) => return Vec::<Endpoint>::new(),
        };

        // For each contact, connect and receive their list of bootstrap contacts
        let mut endpoints: Vec<Endpoint> = vec![];
        for peer in peer_addresses {
            let transport = transport::connect(transport::Endpoint::Tcp(peer))
                .unwrap();
            let contacts_str = match transport.receiver.receive() {
                Ok(message) => message,
                Err(_) => {
                    continue
                },
            };

            match parse_contacts(contacts_str) {
                Ok(contacts) => {
                    for contact in contacts {
                        endpoints.push(contact.endpoint);
                    }
                },
                Err(_) => continue
            }
        }

        endpoints
    }

    fn populate_bootstrap_contacts(config: &Config,
                                   beacon_guid_and_port: &Option<([u8; 16], u16)>,
                                   weak_state: Weak<Mutex<State>>) -> ::contact::Contacts {
        if config.override_default_bootstrap {
            return config.hard_coded_contacts.clone();
        } else {
            let cached_contacts = match beacon_guid_and_port.is_some() {
                // this node "owns" bootstrap file
                true => {
                    lock_mut_state(&mut weak_state.clone(), |state: &mut State| {
                        let mut contacts = ::contact::Contacts::new();
                        if let Some(ref mut handler) = state.bootstrap_handler {
                            contacts = handler.read_file().unwrap_or(vec![]);
                        }
                        Ok(contacts)
                    }).unwrap_or(vec![])
                },
                _ => vec![],
            };
            let beacon_guid = beacon_guid_and_port
                .map(|beacon_guid_and_port| beacon_guid_and_port.0);
            let combined_contacts: Vec<_>
                = Self::seek_peers(beacon_guid, config.beacon_port)
                .iter()
                .map(|x| ::contact::Contact{ endpoint: x.clone()} )
                .chain(config.hard_coded_contacts.clone().into_iter())
                .chain(cached_contacts.into_iter()).collect();

            // remove duplicates
            let mut combined_contacts: ::contact::Contacts =
                combined_contacts.into_iter().unique().collect();

            // remove own endpoints
            if let Ok(own_listening_endpoint) = Self::get_listening_endpoint(weak_state.clone()) {
                combined_contacts.retain(|x| !own_listening_endpoint.contains(&x.endpoint));
            }
            combined_contacts
        }
    }

    fn listen(&mut self, port: Port) -> io::Result<Port> {
        let acceptor = try!(transport::new_acceptor(port));
        let local_port = acceptor.local_port();
        self.own_endpoints = map_external_port(&local_port);

        let mut weak_state = Arc::downgrade(&self.state);

        let _ = lock_mut_state(&mut weak_state, |s| Ok(s.listening_ports.insert(local_port)));

        let _ = thread::Builder::new().name("ConnectionManager listen".to_string()).spawn(move || {
            while let Ok(trans) = transport::accept(&acceptor) {
                let weak_state_copy = weak_state.clone();
                let mut stop_called = false;
                {
                    let _ = lock_mut_state(&weak_state_copy, |state: &mut State| {
                        stop_called = state.stop_called;
                        Ok(())
                    });
                }
                if stop_called {
                    break
                }
                let _ = thread::Builder::new().name("ConnectionManager accept".to_string())
                                              .spawn(move || {
                    let _ = handle_accept(weak_state_copy, trans);
                });
            }
        });

        Ok(local_port)
    }

    /// Return the endpoints other peers can use to connect to. External address
    /// are obtained through UPnP IGD.
    pub fn get_own_endpoints(&self) -> Vec<Endpoint> {
        let mut ret = Vec::with_capacity(self.own_endpoints.len());
        for &(ref local, ref external) in self.own_endpoints.iter() {
            ret.push(local.clone());
            if let Some(ref a) = *external.lock().unwrap() {
                ret.push(a.clone())
            }
        };
        ret
    }
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        self.stop();
    }
}

fn lock_state<T, F: FnOnce(&State) -> io::Result<T>>(state: &WeakState, f: F) -> io::Result<T> {
    state.upgrade().ok_or(io::Error::new(io::ErrorKind::Interrupted,
                                         "Can't dereference weak"))
    .and_then(|arc_state| {
        let opt_state = arc_state.lock();
        match opt_state {
            Ok(s) => f(&s),
            Err(_) => Err(io::Error::new(io::ErrorKind::Interrupted, "?"))
        }
    })
}

fn lock_mut_state<T, F: FnOnce(&mut State) -> io::Result<T>>(state: &WeakState, f: F) -> io::Result<T> {
    state.upgrade().ok_or(io::Error::new(io::ErrorKind::Interrupted,
                                         "Can't dereference weak"))
    .and_then(move |arc_state| {
        let opt_state = arc_state.lock();
        match opt_state {
            Ok(mut s) => f(&mut s),
            Err(_) => Err(io::Error::new(io::ErrorKind::Interrupted, "?"))
        }
    })
}

fn handle_accept(mut state: WeakState, trans: transport::Transport) -> io::Result<Endpoint> {
    let remote_ep = trans.remote_endpoint.clone();
    register_connection(&mut state, trans, Event::NewConnection(remote_ep))
}

fn handle_connect(mut state: WeakState, trans: transport::Transport,
                  is_broadcast_acceptor: bool, is_bootstrap_connection: bool) -> io::Result<Endpoint> {
    if is_bootstrap_connection {
        try!(increment_bootstrap_count(&mut state));
    }

    let remote_ep = trans.remote_endpoint.clone();
    let event = match is_bootstrap_connection {
        true => Event::NewBootstrapConnection(remote_ep),
        false => Event::NewConnection(remote_ep)
    };

    let endpoint = register_connection(&mut state, trans, event);
    if is_broadcast_acceptor {
        if let Ok(ref endpoint) = endpoint {
            let mut contacts = ::contact::Contacts::new();
            contacts.push(::contact::Contact { endpoint: endpoint.clone() });
            // TODO PublicKey for contact required...
            // let public_key = PublicKey::Asym(asymmetricbox::PublicKey([0u8; asymmetricbox::PUBLICKEYBYTES]));
            // TODO: provide a prune list as the second argument to update_contacts
            update_bootstrap_contacts(state, contacts, ::contact::Contacts::new());
        }
    }
    endpoint
}

fn update_bootstrap_contacts(mut weak_state: Weak<Mutex<State>>,
                             new_contacts: ::contact::Contacts,
                             contacts_to_be_pruned: ::contact::Contacts) {
    let _ = lock_mut_state(&mut weak_state, |state: &mut State| {
        if let Some(ref mut handler) = state.bootstrap_handler {
            let _ = handler.update_contacts(new_contacts, contacts_to_be_pruned);
        }
        Ok(())
    });
}

fn increment_bootstrap_count(state: &mut WeakState) -> io::Result<()> {
    lock_mut_state(state, move |s: &mut State| {
        if s.bootstrap_count.0 < s.bootstrap_count.1 {
            s.bootstrap_count.0 += 1;
            return Ok(());
        }
        debug!("Reached max bootstrap connections: {:?}; Resetting further bootstrap connections",
               s.bootstrap_count.0);
        Err(io::Error::new(io::ErrorKind::Other, "Already reached max bootstrap connections"))
    })
}

fn register_connection(state: &mut WeakState, trans: transport::Transport,
                       event_to_user: Event) -> io::Result<Endpoint> {
    let state2 = state.clone();

    lock_mut_state(state, move |s: &mut State| {
        if s.connections.contains_key(&trans.remote_endpoint) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Already connected"))
        }
        let (tx, rx) = mpsc::channel();
        start_writing_thread(state2.clone(), trans.sender, trans.remote_endpoint.clone(), rx);
        start_reading_thread(state2, trans.receiver, trans.remote_endpoint.clone(),
                             s.event_pipe.clone());
        let _ = s.connections.insert(trans.remote_endpoint.clone(), Connection{writer_channel: tx});
        let _ = s.event_pipe.send(event_to_user);
        Ok(trans.remote_endpoint)
    })
}

fn unregister_connection(state: WeakState, his_ep: Endpoint) {
    let _ = lock_mut_state(&state, |s| {
        if s.connections.remove(&his_ep).is_some() {
            // Only send the event if the connection was there
            // to avoid duplicate events.
            let _ = s.event_pipe.send(Event::LostConnection(his_ep));
        }
        Ok(())
    });
}

// pushing events out to event_pipe
fn start_reading_thread(state: WeakState,
                        receiver: transport::Receiver,
                        his_ep: Endpoint,
                        sink: mpsc::Sender<Event>) {
    let _ = thread::Builder::new().name("ConnectionManager reader".to_string()).spawn(move || {
        while let Ok(msg) = receiver.receive() {
            if sink.send(Event::NewMessage(his_ep.clone(), msg)).is_err() {
                break
            }
        }
        unregister_connection(state, his_ep);
    });
}

// pushing messages out to socket
fn start_writing_thread(state: WeakState,
                        mut sender: transport::Sender,
                        his_ep: Endpoint,
                        writer_channel: mpsc::Receiver<Bytes>) {
    let _ = thread::Builder::new().name("ConnectionManager writer".to_string()).spawn(move || {
        for msg in writer_channel.iter() {
            if sender.send(&msg).is_err() {
                break;
            }
        }
        unregister_connection(state, his_ep);
    });
}

// Returns Ok() if at least one connection succeeds
fn bootstrap_off_list(weak_state: WeakState, bootstrap_list: ::contact::Contacts,
                      is_broadcast_acceptor: bool,
                      max_successful_bootstrap_connection: usize) -> io::Result<()> {
    let mut vec_deferred = vec![];

    for contact in bootstrap_list {
        let ws = weak_state.clone();

        let already_connected = try!(lock_state(&ws, |s| {
            Ok(s.connections.contains_key(&contact.endpoint))
        }));

        if already_connected {
            return Ok(())
        }

        vec_deferred.push(Deferred::new(move || {
            match transport::connect(contact.endpoint.clone()) {
                Ok(trans) => {
                    let ep = trans.remote_endpoint.clone();
                    let _ = try!(handle_connect(ws.clone(), trans,
                                                is_broadcast_acceptor, true ));
                    return Ok(ep)
                },
                Err(e) => Err(e),
            }
        }));
    }
    let res = Deferred::first_to_promise(max_successful_bootstrap_connection,
                                         false, vec_deferred,
                                         ControlFlow::ParallelLimit(15))
        .sync();
    let v = match res {
        Ok(v) => v,
        Err(v) => v.into_iter().filter_map(|e| e.ok()).collect(),
    };
    if v.len() > 0 {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other,
                           "No bootstrap node got connected"))
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::thread::spawn;
    use std::thread;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use rustc_serialize::{Decodable, Encodable};
    use cbor::{Encoder, Decoder};
    use transport;
    use transport::{Endpoint, Port};
    use std::sync::{Mutex, Arc};
    use config_handler::write_config_file;
    use std::path::PathBuf;
    use std::net::{SocketAddr, Ipv4Addr, SocketAddrV4, SocketAddrV6};
    use std::fs::remove_file;

    fn encode<T>(value: &T) -> Bytes where T: Encodable
    {
        let mut enc = Encoder::from_memory();
        let _ = enc.encode(&[value]);
        enc.into_bytes()
    }

    fn decode<T>(bytes: Bytes) -> T where T: Decodable {
        let mut dec = Decoder::from_bytes(&bytes[..]);
        dec.decode().next().unwrap().unwrap()
    }

    const  NETWORK_SIZE: u32 = 10;
    const  MESSAGE_PER_NODE: u32 = 10;

     struct Node {
         conn_mgr: ConnectionManager,
         listening_port: Port,
         connected_eps: Arc<Mutex<Vec<Endpoint>>>
     }

     #[derive(Debug)]
     struct Stats {
         new_connections_count: u32,
         messages_count: u32,
         lost_connection_count: u32
     }

     impl Node {
         pub fn new(cm: ConnectionManager) -> Node {
             let ports = cm.get_own_endpoints().into_iter()
                 .map(|ep| ep.get_port()).collect::<Vec<Port>>();
             Node { conn_mgr: cm, listening_port: ports[0].clone(), connected_eps: Arc::new(Mutex::new(Vec::new())) }
         }
     }

     fn get_port(node: &Arc<Mutex<Node>>) -> Port {
         let node = node.clone();
         let node = node.lock().unwrap();
         node.listening_port.clone()
     }

     fn get_connected_eps(node: &Arc<Mutex<Node>>) -> Vec<Endpoint> {
         let node = node.clone();
         let node = node.lock().unwrap();
         let eps = node.connected_eps.clone();
         let connected_eps = eps.lock().unwrap();
         connected_eps.clone()
     }

     struct Network {
         nodes: Vec<Arc<Mutex<Node>>>
     }

     impl Network {
         pub fn add(&mut self) -> (Receiver<Event>, Port, Option<u16>, Arc<Mutex<Vec<Endpoint>>>) {
             let (cm_i, cm_o) = channel();
             let node = Node::new(ConnectionManager::new(cm_i).unwrap());
             let port = node.listening_port.clone();
             let connected_eps = node.connected_eps.clone();
             let beacon_port = node.conn_mgr.get_beacon_acceptor_port();
             self.nodes.push(Arc::new(Mutex::new(node)));
             (cm_o, port, beacon_port, connected_eps)
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

    #[test]
    fn bootstrap() {
        let _cleaner = ::file_handler::ScopedUserAppDirRemover;
        let (cm1_i, _) = channel();
        let _config_file = make_temp_config(None);

        let mut cm1 = ConnectionManager::new(cm1_i).unwrap();

        thread::sleep_ms(1000);
        let _config_file = make_temp_config(cm1.get_beacon_acceptor_port());

        let (cm2_i, cm2_o) = channel();
        let mut cm2 = ConnectionManager::new(cm2_i).unwrap();
        let cm2_eps = cm2.get_own_endpoints().into_iter()
            .map(|ep| ep.get_port()).collect::<Vec<Port>>();
        debug!("   cm2 listening port {}", cm2_eps[0].get_port());

        cm2.bootstrap(1);

        let timeout = ::time::Duration::seconds(5);
        let start = ::time::now();
        let mut result = Err(::std::sync::mpsc::TryRecvError::Empty);
        while ::time::now() < start + timeout && result.is_err() {
            result = cm2_o.try_recv();
            ::std::thread::sleep_ms(100);
        }
        match result {
            Ok(Event::NewBootstrapConnection(ep)) => {
                debug!("NewBootstrapConnection {:?}", ep);
            }
            _ => { assert!(false, "Failed to receive NewBootstrapConnection event")}
        }
        cm1.stop();
        cm2.stop();
    }

    #[test]
    fn connection_manager() {
        // Wait 2 seconds until previous bootstrap test ends. If not, that test connects to these endpoints.
        thread::sleep_ms(2000);
        let run_cm = |cm: ConnectionManager, o: Receiver<Event>| {
            spawn(move || {
                for i in o.iter() {
                    match i {
                        Event::NewConnection(other_ep) => {
                            // debug!("Connected {:?}", other_ep);
                            let _ = cm.send(other_ep.clone(), encode(&"hello world".to_string()));
                        },
                        Event::NewMessage(_, _) => {
                            // debug!("New message from {:?} data:{:?}",
                            //          from_ep, decode::<String>(data));
                            break;
                        },
                        Event::LostConnection(_) => {
                            // debug!("Lost connection to {:?}", other_ep);
                        }
                        Event::NewBootstrapConnection(_) => {}
                    }
                }
                // debug!("done");
            })
        };

        let mut temp_configs = vec![make_temp_config(None)];

        let (cm1_i, cm1_o) = channel();
        let cm1 = ConnectionManager::new(cm1_i).unwrap();
        let cm1_ports = cm1.get_own_endpoints().into_iter()
            .map(|ep| ep.get_port()).collect::<Vec<Port>>();
        let cm1_eps = cm1_ports.iter().map(|p| Endpoint::tcp(("127.0.0.1", p.get_port())));

        temp_configs.push(make_temp_config(cm1.get_beacon_acceptor_port()));

        let (cm2_i, cm2_o) = channel();
        let cm2 = ConnectionManager::new(cm2_i).unwrap();
        let cm2_ports = cm2.get_own_endpoints().into_iter()
            .map(|ep| ep.get_port()).collect::<Vec<Port>>();
        let cm2_eps = cm2_ports.iter().map(|p| Endpoint::tcp(("127.0.0.1", p.get_port())));
        cm2.connect(cm1_eps.collect());
        cm1.connect(cm2_eps.collect());

        let runner1 = run_cm(cm1, cm1_o);
        let runner2 = run_cm(cm2, cm2_o);

        assert!(runner1.join().is_ok());
        assert!(runner2.join().is_ok());
    }

    #[test]
    #[ignore]
    fn network() {
        let run_cm = |tx: Sender<Event>, o: Receiver<Event>, conn_eps: Arc<Mutex<Vec<Endpoint>>>| {
            spawn(move || {
                let count: u32 = 0;
                for i in o.iter() {
                    let _ = tx.send(i.clone());
                    match i {
                        Event::NewConnection(other_ep) => {
                            let mut connected_eps = conn_eps.lock().unwrap();
                            connected_eps.push(other_ep);
                        },
                        Event::NewMessage(_, _) => {
                            if count == MESSAGE_PER_NODE * (NETWORK_SIZE - 1) {
                                break;
                            }
                        },
                        Event::LostConnection(_) => {
                        },
                        Event::NewBootstrapConnection(_) => {}
                    }
                }
                // debug!("done");
            })
        };

        let stats_accumulator = |stats: Arc<Mutex<Stats>>, stats_rx: Receiver<Event>|
            spawn(move || {
                for event in stats_rx.iter() {
                    let mut stat = stats.lock().unwrap();
                    match event {
                            Event::NewConnection(_) => {
                            stat.new_connections_count += 1;
                        },
                        Event::NewMessage(_, data) => {
                            let data_str = decode::<String>(data);
                            if data_str == "EXIT" {
                                break;
                            }
                            stat.messages_count += 1;
                            if stat.messages_count == NETWORK_SIZE * MESSAGE_PER_NODE * (NETWORK_SIZE - 1) {
                                break;
                            }
                        },
                        Event::LostConnection(_) => {
                            stat.lost_connection_count += 1;
                        },
                        Event::NewBootstrapConnection(_) => {}
                    }
                }
            });

        let run_terminate = |ep: Endpoint, tx: Sender<Event>|
            spawn(move || {
                thread::sleep_ms(5000);
                let _ = tx.send(Event::NewMessage(ep, encode(&"EXIT".to_string())));
                });

        let mut network = Network { nodes: Vec::new() };
        let mut temp_configs = vec![make_temp_config(None)];
        let stats = Arc::new(Mutex::new(Stats {new_connections_count: 0, messages_count: 0, lost_connection_count: 0}));
        let (stats_tx, stats_rx) = channel::<Event>();
        let mut runners = Vec::new();
        let mut beacon_port: Option<u16> = None;
        for index in 0..NETWORK_SIZE {
            if index != 0 {
               temp_configs.push(make_temp_config(beacon_port));
            }
            let (receiver, _, port, connected_eps) = network.add();
            if index == 0 {
                beacon_port = port;
            }
            let runner = run_cm(stats_tx.clone(), receiver, connected_eps);
            runners.push(runner);
        }

        let run_stats = stats_accumulator(stats.clone(), stats_rx);

        let mut listening_ports = Vec::new();

        for node in network.nodes.iter() {
            listening_ports.push(get_port(node));
        }

        for node in network.nodes.iter() {
            for port in listening_ports.iter().filter(|&ep| get_port(node).ne(ep)) {
                let node = node.clone();
                let ep = Endpoint::tcp(("127.0.0.1", port.get_port()));
                let _ = spawn(move || {
                    let node = node.lock().unwrap();
                    node.conn_mgr.connect(vec![ep]);
                });
            }
        }

        for node in network.nodes.iter() {
            let mut eps_size = get_connected_eps(node).len();
            while eps_size < (NETWORK_SIZE - 1) as usize {
                eps_size = get_connected_eps(node).len();
            }
        }

        for node in network.nodes.iter() {
            let connected_eps = get_connected_eps(node);
            for end_point in connected_eps.iter() {
                for _ in 0..MESSAGE_PER_NODE {
                    let node = node.clone();
                    let ep = end_point.clone();
                    let _ = spawn(move || {
                        let node = node.lock().unwrap();
                        let _ = node.conn_mgr.send(ep.clone(), encode(&"MESSAGE".to_string()));
                    });
                }
            }
        }

        let _ = run_terminate(Endpoint::tcp(("127.0.0.1", listening_ports[0].get_port())), stats_tx.clone()).join();

        let _ = run_stats.join();

        for _ in 0..NETWORK_SIZE {
            let _ = network.nodes.remove(0);
        }

        for runner in runners.pop() {
            let _ = runner.join();
        }

        let stats_copy = stats.clone();
        let stat = stats_copy.lock().unwrap();
        // It is currently not the case that ConnectionManager guarantees at
        // most one connection between any two peers (although it does make
        // some effort in the `connect` function to do so). It is currently
        // in the TODO. When/if this will be the case, replace the >= operator
        // with ==.
        assert!(stat.new_connections_count >= NETWORK_SIZE * (NETWORK_SIZE - 1));
        assert_eq!(stat.messages_count,  NETWORK_SIZE * MESSAGE_PER_NODE * (NETWORK_SIZE - 1));
        assert_eq!(stat.lost_connection_count, 0);
    }

    #[test]
    fn connection_manager_start() {
        // Wait 2 seconds until previous bootstrap test ends. If not, that test connects to these endpoints.
        thread::sleep_ms(2000);
        let _temp_config = make_temp_config(None);

        let (cm_tx, cm_rx) = channel();
        let cm = ConnectionManager::new(cm_tx).unwrap();
        let cm_listen_ports = cm.get_own_endpoints().into_iter()
            .map(|ep| ep.get_port()).collect::<Vec<Port>>();
        let cm_listen_addrs = cm_listen_ports.iter().map(|p| Endpoint::tcp(("127.0.0.1", p.get_port()))).collect();

        let thread = spawn(move || {
           loop {
                let event = cm_rx.recv();
                if event.is_err() {
                  // debug!("stop listening");
                  break;
                }
                match event.unwrap() {
                    Event::NewMessage(_, _) => {
                        // debug!("received from {} with a new message : {}",
                        //          match endpoint { Endpoint::Tcp(socket_addr) => socket_addr },
                        //          match String::from_utf8(bytes) { Ok(msg) => msg, Err(_) => "unknown msg".to_string() });
                    },
                    Event::NewConnection(_) => {
                        // debug!("adding new node:{}", match endpoint { Endpoint::Tcp(socket_addr) => socket_addr });
                    },
                    Event::LostConnection(_) => {
                        // debug!("dropping node:{}", match endpoint { Endpoint::Tcp(socket_addr) => socket_addr });
                        break;
                    }
                    Event::NewBootstrapConnection(_) => {}
                }
            }
          });
        thread::sleep_ms(100);

        let _ = spawn(move || {
            let _temp_config = make_temp_config(None);
            let (cm_aux_tx, _) = channel();
            let cm_aux = ConnectionManager::new(cm_aux_tx).unwrap();
            // setting the listening port to be greater than 4455 will make the test hanging
            // changing this to cm_beacon_addr will make the test hanging
            cm_aux.connect(cm_listen_addrs);
        }).join();
        thread::sleep_ms(100);

        let _ = thread.join();
    }

    #[test]
    fn bootstrap_off_list_connects() {
        let acceptor = transport::new_acceptor(Port::Tcp(0)).unwrap();
        let addr = match acceptor {
            transport::Acceptor::Tcp(_, listener) => listener.local_addr()
                .unwrap(),
            _ => panic!("Unable to create a new connection"),
        };
        let addr = match addr {
            SocketAddr::V4(a) => if a.ip().is_unspecified() {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1),
                                                 a.port()))
            } else {
                SocketAddr::V4(a)
            },
            SocketAddr::V6(a) => if a.ip().is_unspecified() {
                SocketAddr::V6(SocketAddrV6::new("::1".parse().unwrap(),
                                                 a.port(), a.flowinfo(),
                                                 a.scope_id()))
            } else {
                SocketAddr::V6(a)
            },
        };
        let ep = Endpoint::Tcp(addr);
        let state = Arc::new(Mutex::new(super::State{ event_pipe: channel().0,
                                                      connections: HashMap::new(),
                                                      listening_ports: HashSet::new(),
                                                      bootstrap_handler: None,
                                                      stop_called: false,
                                                      bootstrap_count: (0,1),
                                                    }));
        assert!(super::bootstrap_off_list(Arc::downgrade(&state), vec![], false, 15).is_err());
        assert!(super::bootstrap_off_list(Arc::downgrade(&state),
                                          vec![::contact::Contact{endpoint: ep.clone()}], false, 15)
                .is_ok());
    }

    #[test]
    fn bootstrap_off_list_connects_multiple() {
        let max_count = 4;
        let available_peer_count = 10;

        let mut contacts = vec![];
        let mut acceptors = vec![];
        loop {
            let acceptor = transport::new_acceptor(Port::Tcp(0)).unwrap();
            let addr = match acceptor {
                transport::Acceptor::Tcp(_, ref listener) => listener.local_addr()
                    .unwrap(),
                _ => panic!("Unable to create a new connection"),
            };
            let addr = match addr {
                SocketAddr::V4(a) => if a.ip().is_unspecified() {
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1),
                                                     a.port()))
                } else {
                    SocketAddr::V4(a)
                },
                SocketAddr::V6(a) => if a.ip().is_unspecified() {
                    SocketAddr::V6(SocketAddrV6::new("::1".parse().unwrap(),
                                                     a.port(), a.flowinfo(),
                                                     a.scope_id()))
                } else {
                    SocketAddr::V6(a)
                },
            };
            contacts.push(::contact::Contact{endpoint: Endpoint::Tcp(addr)});
            acceptors.push(acceptor);
            if contacts.len() == available_peer_count {
                break;
            }
        }

        let (tx, rx) = channel();
        let state = Arc::new(Mutex::new(super::State{ event_pipe: tx,
                                                      connections: HashMap::new(),
                                                      listening_ports: HashSet::new(),
                                                      bootstrap_handler: None,
                                                      stop_called: false,
                                                      bootstrap_count: (0,max_count),
                                                    }));
        assert!(super::bootstrap_off_list(Arc::downgrade(&state), vec![], false, 15).is_err());
        assert!(super::bootstrap_off_list(Arc::downgrade(&state),
                                          contacts.clone(), false, max_count).is_ok());

        // read if rx gets max_count bootstrap eps
        let mut received_event_count = 0;
        while received_event_count < max_count {
            match rx.recv() {
                Ok(Event::NewBootstrapConnection(ep)) => {
                    assert!(contacts.contains(&::contact::Contact{endpoint: ep}));
                    received_event_count += 1;
                },
                _ => { panic!("Unexpected event !")},
            }
        }

        // should not get any more than max bs connections
        for _ in 0..10 {
            thread::sleep_ms(100);
            assert!(rx.try_recv().is_err());
        }
    }
}
