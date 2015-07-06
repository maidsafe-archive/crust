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

//use cbor;
//use sodiumoxide::crypto::asymmetricbox;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, mpsc, Mutex, Weak};
use std::thread;
use std::net::IpAddr;

use beacon;
use bootstrap_handler::{BootstrapHandler, Contacts, Contact, parse_contacts};
use getifaddrs::getifaddrs;
use transport;
use transport::{Endpoint, Port};

use asynchronous::{Deferred,ControlFlow};

/// Type used to represent serialised data in a message.
pub type Bytes = Vec<u8>;

type WeakState = Weak<Mutex<State>>;

/// A structure representing a connection manager
pub struct ConnectionManager {
    state: Arc<Mutex<State>>,
    beacon_guid_and_port: Option<(beacon::GUID, u16)>,
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
}

struct Connection {
    writer_channel: mpsc::Sender<Bytes>,
}

struct State {
    event_pipe: mpsc::Sender<Event>,
    connections: HashMap<Endpoint, Connection>,
    listening_ports: HashSet<Port>,
    stop_called: bool,
}

impl ConnectionManager {
    /// Constructs a connection manager. User needs to create an asynchronous channel, and provide
    /// the sender half to this method. Receiver will receive all `Event`s from this library.
    pub fn new(event_pipe: mpsc::Sender<Event>) -> ConnectionManager {
        let state = Arc::new(Mutex::new(State{ event_pipe: event_pipe,
                                               connections: HashMap::new(),
                                               listening_ports: HashSet::new(),
                                               stop_called: false,
                                             }));
        ConnectionManager { state: state, beacon_guid_and_port: None, }
    }

    /// Starts listening on all supported protocols. Specified hint will be tried first. If it fails
    /// to start on these, it defaults to random / OS provided endpoints for each supported
    /// protocol. The actual endpoints used will be returned on which it started listening for each
    /// protocol.
    /// if beacon port == 0 => a random port is taken and returned by beacon
    /// if beacon port != 0 => an attempt to get the port is made by beacon and the callee will be informed of the attempt
    /// if beacon port == None => 5483 is tried
    /// if beacon succeeds in starting the udp listener, the coresponding port is returned
    // FIXME: Returning io::Result seems pointless since we always return Ok.
    pub fn start_listening(&mut self, mut hint: Vec<Port>, beacon_port: Option<u16>) ->
            io::Result<(Vec<Port>, Option<u16>)> {
        // We need to check for an instance of each supported protocol in the hint vector.  For any
        // protocol that doesn't have an entry, we should inject one (either random or 0).  For now
        // we're only supporting TCP, so...
        let beacon_port: u16 = beacon_port.unwrap_or(5483);

        let mut used_beacon_port: Option<u16> = None;
        let ws = self.state.downgrade();

        let mut listening_ports = Vec::new();
        self.beacon_guid_and_port = match beacon::BroadcastAcceptor::new(beacon_port) {
            Ok(acceptor) => {
                let beacon_guid_and_port = (acceptor.beacon_guid(), acceptor.beacon_port());
                used_beacon_port = Some(beacon_guid_and_port.1);
                // let public_key =
                //     PublicKey::Asym(asymmetricbox::PublicKey([0u8; asymmetricbox::PUBLICKEYBYTES]));

                let mut bootstrap_handler = BootstrapHandler::new();

                if hint.is_empty() {  // overriding botstrap file if hint provided in api, remove once api is changed
                    hint.push(bootstrap_handler.read_preferred_port()
                              .unwrap_or(Port::Tcp(0)));
                }

                for h in &hint {
                   self.listen(h);
                }

                listening_ports = try!(lock_state(&ws, |s| {
                    let buf: Vec<Port> = s.listening_ports.iter().map(|s| s.clone()).collect();
                    Ok(buf)
                }));

                let mut contacts = Contacts::new();
                let listening_ips = getifaddrs();
                for port in &listening_ports {
                    for ip in &listening_ips {
                        contacts.push(Contact { endpoint: Endpoint::tcp((ip.addr.clone(), port.get_port())) });
                    }
                }

                let _ = bootstrap_handler.add_contacts(contacts);

                let _ = thread::Builder::new().name("ConnectionManager beacon acceptor".to_string())
                                              .spawn(move || {
                    while let Ok(mut transport) = acceptor.accept() {
                        let handler = BootstrapHandler::new();
                        let read_contacts = handler.get_serialised_contacts();
                        if read_contacts.is_ok() {
                            let _ = transport.sender.send(&read_contacts.unwrap());
                        }
                    }
                });
                Some(beacon_guid_and_port)
            },
            Err(_) => None
        };

        if self.beacon_guid_and_port.is_none() {
            if hint.is_empty() {
                hint.push(Port::Tcp(0));
            }

            for h in &hint {
                self.listen(h);
            }

            listening_ports = try!(lock_state(&ws, |s| {
                let buf: Vec<Port> = s.listening_ports.iter().map(|s| s.clone()).collect();
                Ok(buf)
            }));
        }
        Ok((listening_ports, used_beacon_port))
    }

    /// For API compatibilty, return a vector of listening endpoints
    pub fn start_listening2(&mut self, hint: Vec<Port>, beacon_port: Option<u16>) ->
            io::Result<(Vec<Endpoint>, Option<u16>)> {
        let ports_and_beacon = try!(self.start_listening(hint, beacon_port));
        let mut endpoints = Vec::<Endpoint>::new();
        for port in ports_and_beacon.0 {
            match port {
                Port::Tcp(p) => {
                    for ifaddr in getifaddrs() {
                        endpoints.push(match ifaddr.addr {
                            IpAddr::V4(a) => Endpoint::tcp((a, p)),
                            IpAddr::V6(a) => Endpoint::tcp((a, p)),
                        });
                    }
                },
                Port::Utp(p) => {
                    for ifaddr in getifaddrs() {
                        endpoints.push(match ifaddr.addr {
                            IpAddr::V4(a) => Endpoint::utp((a, p)),
                            IpAddr::V6(a) => Endpoint::utp((a, p)),
                        });
                    }
                },
            }
        }
        Ok((endpoints, ports_and_beacon.1))
    }


    // NOTE this can be reused at other places.
    fn get_listening_endpoint(&self) -> io::Result<(Vec<Endpoint>)> {
        let ws = self.state.downgrade();
        let listening_ports = try!(lock_state(&ws, |s| {
            let buf: Vec<Port> = s.listening_ports.iter().map(|s| s.clone()).collect();
            Ok(buf)
        }));

        let mut endpoints = Vec::<Endpoint>::new();
        for port in listening_ports {
            match port {
                Port::Tcp(p) => {
                    for ifaddr in getifaddrs() {
                        endpoints.push(match ifaddr.addr {
                            IpAddr::V4(a) => Endpoint::tcp((a, p)),
                            IpAddr::V6(a) => Endpoint::tcp((a, p)),
                        });
                    }
                },
                Port::Utp(p) => {
                    for ifaddr in getifaddrs() {
                        endpoints.push(match ifaddr.addr {
                            IpAddr::V4(a) => Endpoint::utp((a, p)),
                            IpAddr::V6(a) => Endpoint::utp((a, p)),
                        });
                    }
                },
            }
        }
        Ok(endpoints)
    }

    /// This method tries to connect (bootstrap to exisiting network) to the default or provided
    /// list of bootstrap nodes.
    ///
    /// If `bootstrap_list` is `None`, it will attempt to read a local cached file to populate the
    /// list.  It will then try to connect to all of the endpoints in the list.  It will return
    /// once a connection with any of the endpoints is established with Ok(Endpoint) and it will
    /// drop all other ongoing attempts.  If this fails and `beacon_port` is `Some`, it will try to
    /// use the beacon port to connect to a peer on the same LAN.
    /// For more details on bootstrap cache file refer
    /// https://github.com/maidsafe/crust/blob/master/docs/bootstrap.md
    ///
    /// If `bootstrap_list` is `Some`, it will try to connect to all of the endpoints in the list.
    /// It will return once a connection with any of the endpoints is established with Ok(Endpoint)
    /// and it will drop all other ongoing attempts.  Note that `beacon_port` has no effect if
    /// `bootstrap_list` is `Some`; i.e. passing an explicit list ensures we only get connected to
    /// one of the nodes on the list - we don't fall back to use the beacon protocol.
    ///
    /// It will return Err if it fails to connect to any peer.
    pub fn bootstrap(&self, bootstrap_list: Option<Vec<Endpoint>>, beacon_port: Option<u16>) ->
            io::Result<Endpoint> {
        let port: u16 = beacon_port.unwrap_or(5483);
        match bootstrap_list {
            Some(list) => self.bootstrap_off_list(list),
            None => {
                let mut combined_endpoint_list = self.seek_peers(port);
                if self.beacon_guid_and_port.is_some() {  // this node owns bs file
                    let handler = BootstrapHandler::new();
                    match handler.read_bootstrap_file() {
                        Ok(read_contacts) => {
                            for contacts in read_contacts.contacts {
                                combined_endpoint_list.push(contacts.endpoint);
                            }
                            for contacts in read_contacts.hard_coded_contacts {
                                combined_endpoint_list.push(contacts.endpoint);
                            }
                        },
                        _ => {},
                    }
                }
                self.bootstrap_off_list(combined_endpoint_list)
            },
        }
    }

    /// This should be called before destroying an instance of a ConnectionManager to allow the
    /// listener threads to join.  Once called, the ConnectionManager should be destroyed.
    pub fn stop(&mut self) {
        if let Some(beacon_guid_and_port) = self.beacon_guid_and_port {
            beacon::BroadcastAcceptor::stop(&beacon_guid_and_port);
            self.beacon_guid_and_port = None;
        }
        let mut listening_ports = Vec::<Port>::new();
        let weak_state = self.state.downgrade();
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
        // println!("connection_manager::stop There are {} TCP ports being listened on", listening_ports.len());
        for port in listening_ports {
            let _ = transport::connect(Endpoint::tcp(("127.0.0.1", port.get_port())));
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
        let ws = self.state.downgrade();
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
                                        is_broadcast_acceptor));
                if result.is_ok() { return; }
            }
        });
    }

    /// Sends a message to specified address (endpoint). Returns Ok(()) if the sending might
    /// succeed, and returns an Err if the address is not connected. Return value of Ok does not
    /// mean that the data will be received. It is possible for the corresponding connection to hang
    /// up immediately after this function returns Ok.
    pub fn send(&self, endpoint: Endpoint, message: Bytes) -> io::Result<()> {
        let ws = self.state.downgrade();

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
        let mut ws = self.state.downgrade();
        let _ = lock_mut_state(&mut ws, |s: &mut State| {
            let _ = s.connections.remove(&endpoint);
            Ok(())
        });
    }

    /// Uses beacon to try and collect potential bootstrap endpoints from peers on the same subnet.
    fn seek_peers(&self, beacon_port: u16) -> Vec<Endpoint> {
        // Retrieve list of peers' TCP listeners who are on same subnet as us
        let beacon_guid = self.beacon_guid_and_port
            .map(|beacon_guid_and_port| beacon_guid_and_port.0);
        let peer_addresses = match beacon::seek_peers(beacon_port, beacon_guid) {
            Ok(peers) => peers,
            Err(_) => return Vec::<Endpoint>::new(),
        };

        // For each contact, connect and receive their list of bootstrap contacts
        let mut endpoints: Vec<Endpoint> = vec![];
        for peer in peer_addresses {
            let transport = transport::connect(transport::Endpoint::Tcp(peer)).unwrap();
            let contacts_str = match transport.receiver.receive() {
                Ok(message) => message,
                Err(_) => {
                    continue
                },
            };

            match parse_contacts(contacts_str) {
                Some(contacts) => {
                    for contact in contacts {
                        endpoints.push(contact.endpoint);
                    }
                },
                None => continue
            }
        }

        endpoints
    }

    fn bootstrap_off_list(&self, mut bootstrap_list: Vec<Endpoint>) -> io::Result<Endpoint> {
        // remove own endpoints
        let own_listening_endpoint = try!(self.get_listening_endpoint());
        bootstrap_list.retain(|x| !own_listening_endpoint.contains(&x));

        let mut vec_deferred = vec![];
        for endpoint in bootstrap_list {
            let state_cloned = self.state.clone();
            let beacon_guid_and_port_is_some = self.beacon_guid_and_port.is_some();
            vec_deferred.push(Deferred::new(move || {
                match transport::connect(endpoint.clone()) {
                    Ok(trans) => {
                        let ep = trans.remote_endpoint.clone();
                        let _ = try!(handle_connect(state_cloned.downgrade(), trans,
                                                    beacon_guid_and_port_is_some ));
                        return Ok(ep)
                    },
                    Err(e) => Err(e),
                }
            }));
        }
        let res = Deferred::first_to_promise(1,false,vec_deferred, ControlFlow::ParallelLimit(15)).sync();
        if let Ok(v) = res {
            if v.len() > 0 { return Ok(v[0].clone()) }
        }
        // FIXME: The result should probably be Option<Endpoint>
        Err(io::Error::new(io::ErrorKind::Other, "No bootstrap node got connected"))
    }

    fn listen(&self, port: &Port) {
        let acceptor = transport::new_acceptor(port).unwrap();
        let local_port = acceptor.local_port();

        let mut weak_state = self.state.downgrade();

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
    }
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        self.stop();
    }
}

// fn notify_user(state: &WeakState, event: Event) -> io::Result<()> {
//     lock_state(state, |s| {
//         s.event_pipe.send(event)
//         .map_err(|_|io::Error::new(io::ErrorKind::BrokenPipe, "failed to notify_user"))
//     })
// }

fn lock_state<T, F: FnOnce(&State) -> io::Result<T>>(state: &WeakState, f: F) -> io::Result<T> {
    state.upgrade().ok_or(io::Error::new(io::ErrorKind::Interrupted,
                                         "Can't dereference weak"))
    .and_then(|arc_state| {
        let opt_state = arc_state.lock();
        match opt_state {
            Ok(s)  => f(&s),
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
            Ok(mut s)  => f(&mut s),
            Err(_) => Err(io::Error::new(io::ErrorKind::Interrupted, "?"))
        }
    })
}

fn handle_accept(mut state: WeakState, trans: transport::Transport) -> io::Result<Endpoint> {
    let remote_ep = trans.remote_endpoint.clone();
    register_connection(&mut state, trans, Event::NewConnection(remote_ep))
}

fn handle_connect(mut state: WeakState, trans: transport::Transport,
                  is_broadcast_acceptor: bool) -> io::Result<Endpoint> {
    let remote_ep = trans.remote_endpoint.clone();
    let endpoint = register_connection(&mut state, trans, Event::NewConnection(remote_ep));
    if is_broadcast_acceptor {
        if let Ok(ref endpoint) = endpoint {
            let mut contacts = Contacts::new();
            // TODO PublicKey for contact required...
            // let public_key = PublicKey::Asym(asymmetricbox::PublicKey([0u8; asymmetricbox::PUBLICKEYBYTES]));
            contacts.push(Contact {  endpoint: endpoint.clone()});
            let mut bootstrap_handler = BootstrapHandler::new();
            let _ = bootstrap_handler.add_contacts(contacts);
        }
    }
    endpoint
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


#[cfg(test)]
mod test {
    use super::*;
    use std::thread::spawn;
    use std::thread;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use rustc_serialize::{Decodable, Encodable};
    use cbor::{Encoder, Decoder};
    use transport::{Endpoint, Port};
    use std::sync::{Mutex, Arc};

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
         pub fn new(mut cm: ConnectionManager, port: u16) -> (Node, Option<u16>) {
             let (ports, beacon_port) =  cm.start_listening(vec![Port::Tcp(0)], Some(port)).unwrap();
             (Node { conn_mgr: cm, listening_port: ports[0].clone(), connected_eps: Arc::new(Mutex::new(Vec::new())) }, beacon_port)
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
         pub fn add(&mut self, beacon_port: u16) -> (Receiver<Event>, Port, Option<u16>, Arc<Mutex<Vec<Endpoint>>>) {
             let (cm_i, cm_o) = channel();
             let (node, beacon_port) = Node::new(ConnectionManager::new(cm_i), beacon_port);
             let port = node.listening_port.clone();
             let connected_eps = node.connected_eps.clone();
             self.nodes.push(Arc::new(Mutex::new(node)));
             (cm_o, port, beacon_port, connected_eps)
         }
     }

#[test]
    fn bootstrap_tcp() {
        let (cm1_i, _) = channel();
        let mut cm1 = ConnectionManager::new(cm1_i);
        let (cm1_eps, beacon_port) = cm1.start_listening(vec![Port::Tcp(0)], Some(0u16)).unwrap();
        println!("   cm1 listening port {} beaconing port {}", cm1_eps[0].get_port(), beacon_port.unwrap());

        thread::sleep_ms(1000);
        let (cm2_i, _) = channel();
        let mut cm2 = ConnectionManager::new(cm2_i);
        let (cm2_eps, _) = cm2.start_listening(vec![Port::Tcp(0)], beacon_port.clone()).unwrap();
        println!("   cm2 listening port {}", cm2_eps[0].get_port());
        match cm2.bootstrap(None, beacon_port) {
            Ok(ep) => { assert_eq!(ep.get_address().port(), cm1_eps[0].get_port()); },
            Err(_) => { panic!("Failed to bootstrap"); }
        }
    }

#[test]
    fn bootstrap_utp() {
        let (cm1_i, _) = channel();
        let mut cm1 = ConnectionManager::new(cm1_i);
        let (cm1_eps, beacon_port) = cm1.start_listening(vec![Port::Utp(0)], Some(0u16)).unwrap();
        println!("   cm1 listening port {} beaconing port {}", cm1_eps[0].get_port(), beacon_port.unwrap());

        thread::sleep_ms(1000);
        let (cm2_i, _) = channel();
        let mut cm2 = ConnectionManager::new(cm2_i);
        let (cm2_eps, _) = cm2.start_listening(vec![Port::Utp(0)], beacon_port.clone()).unwrap();
        println!("   cm2 listening port {}", cm2_eps[0].get_port());
        if cm2.bootstrap(None, beacon_port).is_err() {
            panic!("Failed to bootstrap");
        }
    }

#[test]
    fn connection_manager_tcp() {
        // Wait 2 seconds until previous bootstrap test ends. If not, that test connects to these endpoints.
        thread::sleep_ms(2000);
        let run_cm = |cm: ConnectionManager, o: Receiver<Event>| {
            spawn(move || {
                for i in o.iter() {
                    match i {
                        Event::NewConnection(other_ep) => {
                            // println!("Connected {:?}", other_ep);
                            let _ = cm.send(other_ep.clone(), encode(&"hello world".to_string()));
                        },
                        Event::NewMessage(_, _) => {
                            // println!("New message from {:?} data:{:?}",
                            //          from_ep, decode::<String>(data));
                            break;
                        },
                        Event::LostConnection(_) => {
                            // println!("Lost connection to {:?}", other_ep);
                        }
                    }
                }
                // println!("done");
            })
        };

        let (cm1_i, cm1_o) = channel();
        let mut cm1 = ConnectionManager::new(cm1_i);
        let (cm1_ports, beacon_port) = cm1.start_listening(vec![Port::Tcp(0)], Some(0u16)).unwrap();
        let cm1_eps = cm1_ports.iter().map(|p| Endpoint::tcp(("127.0.0.1", p.get_port())));

        let (cm2_i, cm2_o) = channel();
        let mut cm2 = ConnectionManager::new(cm2_i);
        let (cm2_ports, _) = cm2.start_listening(vec![Port::Tcp(0)], beacon_port.clone()).unwrap();
        let cm2_eps = cm2_ports.iter().map(|p| Endpoint::tcp(("127.0.0.1", p.get_port())));
        cm2.connect(cm1_eps.collect());
        cm1.connect(cm2_eps.collect());

        let runner1 = run_cm(cm1, cm1_o);
        let runner2 = run_cm(cm2, cm2_o);

        assert!(runner1.join().is_ok());
        assert!(runner2.join().is_ok());
    }

#[test]
    fn connection_manager_utp() {
        // Wait 2 seconds until previous bootstrap test ends. If not, that test connects to these endpoints.
        thread::sleep_ms(2000);
        let run_cm = |cm: ConnectionManager, o: Receiver<Event>| {
            spawn(move || {
                for i in o.iter() {
                    match i {
                        Event::NewConnection(other_ep) => {
                            // println!("Connected {:?}", other_ep);
                            let _ = cm.send(other_ep.clone(), encode(&"hello world".to_string()));
                        },
                        Event::NewMessage(_, _) => {
                            // println!("New message from {:?} data:{:?}",
                            //          from_ep, decode::<String>(data));
                            break;
                        },
                        Event::LostConnection(_) => {
                            // println!("Lost connection to {:?}", other_ep);
                        }
                    }
                }
                // println!("done");
            })
        };

        let (cm1_i, cm1_o) = channel();
        let mut cm1 = ConnectionManager::new(cm1_i);
        let (cm1_ports, beacon_port) = cm1.start_listening(vec![Port::Utp(0)], Some(0u16)).unwrap();
        let cm1_eps = cm1_ports.iter().map(|p| Endpoint::utp(("127.0.0.1", p.get_port())));

        let (cm2_i, cm2_o) = channel();
        let mut cm2 = ConnectionManager::new(cm2_i);
        let (cm2_ports, _) = cm2.start_listening(vec![Port::Utp(0)], beacon_port.clone()).unwrap();
        let cm2_eps = cm2_ports.iter().map(|p| Endpoint::utp(("127.0.0.1", p.get_port())));
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
                        }
                    }
                }
                // println!("done");
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
                        }
                    }
                }
            });

        let run_terminate = |ep: Endpoint, tx: Sender<Event>|
            spawn(move || {
                thread::sleep_ms(5000);
                let _ = tx.send(Event::NewMessage(ep, encode(&"EXIT".to_string())));
                });


        let mut network = Network { nodes: Vec::new() };
        let stats = Arc::new(Mutex::new(Stats {new_connections_count: 0, messages_count: 0, lost_connection_count: 0}));
        let (stats_tx, stats_rx) = channel::<Event>();
        let mut runners = Vec::new();
        let mut beacon_port: u16 = 0;
        for _ in 0..NETWORK_SIZE {
            let (receiver, _, port, connected_eps) = network.add(beacon_port);
            if let Some(port_no) = port {
                beacon_port = port_no
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
    fn connection_manager_start_tcp() {
        // Wait 2 seconds until previous bootstrap test ends. If not, that test connects to these endpoints.
        thread::sleep_ms(2000);
        let (cm_tx, cm_rx) = channel();
        let mut cm = ConnectionManager::new(cm_tx);
        let cm_listen_ports = match cm.start_listening(vec![Port::Tcp(4455)], Some(5483)) {
            Ok(result) => result.0,
            Err(_) => panic!("main connection manager start_listening failure")
        };
        let cm_listen_addrs = cm_listen_ports.iter().map(|p| Endpoint::tcp(("127.0.0.1", p.get_port()))).collect();

        let thread = spawn(move || {
           loop {
                let event = cm_rx.recv();
                if event.is_err() {
                  // println!("stop listening");
                  break;
                }
                match event.unwrap() {
                    Event::NewMessage(_, _) => {
                        // println!("received from {} with a new message : {}",
                        //          match endpoint { Endpoint::Tcp(socket_addr) => socket_addr },
                        //          match String::from_utf8(bytes) { Ok(msg) => msg, Err(_) => "unknown msg".to_string() });
                    },
                    Event::NewConnection(_) => {
                        // println!("adding new node:{}", match endpoint { Endpoint::Tcp(socket_addr) => socket_addr });
                    },
                    Event::LostConnection(_) => {
                        // println!("dropping node:{}", match endpoint { Endpoint::Tcp(socket_addr) => socket_addr });
                        break;
                    }
                }
            }
          });
        thread::sleep_ms(100);

        let _ = spawn(move || {
            let (cm_aux_tx, _) = channel();
            let mut cm_aux = ConnectionManager::new(cm_aux_tx);
            // setting the listening port to be greater than 4455 will make the test hanging
            let _ = match cm_aux.start_listening(vec![Port::Tcp(4454)], None) {
                Ok(result) => {
                      // println!("aux listening on {} ",
                      //          match result.0[0].clone() { Endpoint::Tcp(socket_addr) => { socket_addr } });
                      result.0[0].clone()
                    },
                Err(_) => panic!("aux connection manager start_listening failure")
            };
            // changing this to cm_beacon_addr will make the test hanging
            cm_aux.connect(cm_listen_addrs);
        }).join();
        thread::sleep_ms(100);

        let _ = thread.join();
    }

#[test]
    fn connection_manager_start_utp() {
        // Wait 2 seconds until previous bootstrap test ends. If not, that test connects to these endpoints.
        thread::sleep_ms(2000);
        let (cm_tx, cm_rx) = channel();
        let mut cm = ConnectionManager::new(cm_tx);
        let cm_listen_ports = match cm.start_listening(vec![Port::Utp(4455)], Some(5483)) {
            Ok(result) => result.0,
            Err(_) => panic!("main connection manager start_listening failure")
        };
        let cm_listen_addrs = cm_listen_ports.iter().map(|p| Endpoint::utp(("127.0.0.1", p.get_port()))).collect();

        let thread = spawn(move || {
           loop {
                let event = cm_rx.recv();
                if event.is_err() {
                  // println!("stop listening");
                  break;
                }
                match event.unwrap() {
                    Event::NewMessage(_, _) => {
                        // println!("received from {} with a new message : {}",
                        //          match endpoint { Endpoint::Tcp(socket_addr) => socket_addr },
                        //          match String::from_utf8(bytes) { Ok(msg) => msg, Err(_) => "unknown msg".to_string() });
                    },
                    Event::NewConnection(_) => {
                        // println!("adding new node:{}", match endpoint { Endpoint::Tcp(socket_addr) => socket_addr });
                    },
                    Event::LostConnection(_) => {
                        // println!("dropping node:{}", match endpoint { Endpoint::Tcp(socket_addr) => socket_addr });
                        break;
                    }
                }
            }
          });
        thread::sleep_ms(100);

        let _ = spawn(move || {
            let (cm_aux_tx, _) = channel();
            let mut cm_aux = ConnectionManager::new(cm_aux_tx);
            // setting the listening port to be greater than 4455 will make the test hanging
            let _ = match cm_aux.start_listening(vec![Port::Utp(4454)], None) {
                Ok(result) => {
                      // println!("aux listening on {} ",
                      //          match result.0[0].clone() { Endpoint::Tcp(socket_addr) => { socket_addr } });
                      result.0[0].clone()
                    },
                Err(_) => panic!("aux connection manager start_listening failure")
            };
            // changing this to cm_beacon_addr will make the test hanging
            cm_aux.connect(cm_listen_addrs);
        }).join();
        thread::sleep_ms(100);

        let _ = thread.join();
    }
}
