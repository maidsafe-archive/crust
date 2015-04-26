// Copyright 2015 MaidSafe.net limited
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://maidsafe.net/network-platform-licensing
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations relating to
// use of the SAFE Network Software.

use std::io::Error as IoError;
use std::io;
use std::collections::{HashMap, HashSet};
use std::thread::spawn;
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, Weak};
use std::sync::mpsc;
use transport::{Endpoint, Port};
use transport;
use beacon;

pub type Bytes = Vec<u8>;
pub type IoResult<T> = Result<T, IoError>;

// FIXME: Do we need these? If yes, do they need to be public?
pub type IoReceiver<T> = Receiver<T>;
pub type IoSender<T>   = Sender<T>;

type WeakState = Weak<Mutex<State>>;

/// A structure representing a connection manager
pub struct ConnectionManager {
    state: Arc<Mutex<State>>,
}

/// Enum representing different events that will be sent over the asynchronous channel to the user
/// of this module.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Event {
    NewMessage(Endpoint, Bytes),
    NewConnection(Endpoint),
    LostConnection(Endpoint),
}

struct Connection {
    writer_channel: mpsc::Sender<Bytes>,
}

struct State {
    event_pipe:    IoSender<Event>,
    connections:   HashMap<Endpoint, Connection>,
    listening_eps: HashSet<Endpoint>,
}

impl ConnectionManager {
    /// Constructs a connection manager. User needs to create an asynchronous channel, and provide
    /// the sender half to this method. Receiver will receive all `Event`s from this library.
    pub fn new(event_pipe: IoSender<Event>) -> ConnectionManager {
        let state = Arc::new(Mutex::new(State{ event_pipe:    event_pipe,
                                               connections:   HashMap::new(),
                                               listening_eps: HashSet::new()
                                             }));
        ConnectionManager { state: state }
    }

    /// Starts listening on all supported protocols. Specified hint will be tried first. If it fails
    /// to start on these, it defaults to random / OS provided endpoints for each supported
    /// protocol. The actual endpoints used will be returned on which it started listening for each
    /// protocol.
    /// if beacon port == 0 => a random port is taken and returned by beacon
    /// if beacon port != 0 => an attempt to get the port is made by beacon and the callee will be informed of the attempt
    /// if beacon port == None => 5483 is tried
    /// if beacon succeeds in starting the udp listener, the coresponding port is returned
    pub fn start_listening(&self, hint: Vec<Port>, beacon_port: Option<u16>) -> IoResult<(Vec<Endpoint>, Option<u16>)> {
        // FIXME: Returning IoResult seems pointless since we always return Ok.
        let end_points = hint.iter().filter_map(|port| self.listen(port).ok()).collect::<Vec<_>>();
        let port = match end_points[0].clone() {
            Endpoint::Tcp(socket_addr) => { match beacon::listen_for_broadcast(socket_addr, beacon_port.clone()) {
                                                    Ok(used_port) => Some(used_port),
                                                    Err(_) => None
                                               }}
        };
        Ok((end_points, port))
    }

    /// This method tries to connect (bootstrap to exisiting network) to the default or provided
    /// list of bootstrap nodes.
    ///
    /// If `bootstrap_list` is `Some`, the method will try to connect to all of the endpoints
    /// specified in `bootstrap_list`. It will return once connection with any of the endpoints is
    /// established with Ok(Endpoint) and it will drop all other ongoing attempts. Returns Err if it
    /// fails to connect to any of the endpoints specified.
    ///
    /// If `bootstrap_list` is `None`, it will use default methods to bootstrap to the existing
    /// network. Default methods includes beacon system for finding nodes on a local network and
    /// bootstrap handler which will attempt to reconnect to any previous "direct connected" nodes.
    /// In both cases, this method blocks until it gets one successful connection or all the
    /// endpoints are tried and have failed.
    pub fn bootstrap(&self, bootstrap_list: Option<Vec<Endpoint>>, beacon_port: Option<u16>) -> IoResult<Endpoint> {
        match bootstrap_list {
            Some(list) => self.bootstrap_off_list(list),
            None       => self.bootstrap_off_list(self.get_stored_bootstrap_endpoints(beacon_port)),
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
        let mut listening = HashSet::<Endpoint>::new();
        {
            let _ = lock_mut_state(& ws, |s: &mut State| {
                for itr in s.listening_eps.iter() {
                    listening.insert(itr.clone());
                }
                Ok(())
            });
        }
        spawn(move || {
            for endpoint in &endpoints {
                for itr in listening.iter() {
                    if itr.is_master(endpoint) {
                        let ws = ws.clone();
                        let result = transport::connect(endpoint.clone())
                                     .and_then(|trans| handle_connect(ws, trans));
                        if result.is_ok() { return; }
                    }
                }
            }
        });
    }

    /// Sends a message to specified address (endpoint). Returns Ok(()) if the sending might
    /// succeed, and returns an Err if the address is not connected. Return value of Ok does not
    /// mean that the data will be received. It is possible for the corresponding connection to hang
    /// up immediately after this function returns Ok.
    pub fn send(&self, endpoint: Endpoint, message: Bytes) -> IoResult<()> {
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
            s.connections.remove(&endpoint);
            Ok(())
        });
    }

    pub fn get_stored_bootstrap_endpoints(&self, beacon_port: Option<u16>) -> Vec<Endpoint> {
        beacon::seek_peers(beacon_port).iter().map(|&socket_address| Endpoint::Tcp(socket_address)).collect::<Vec<_>>()
    }

    fn bootstrap_off_list(&self, bootstrap_list: Vec<Endpoint>) -> IoResult<Endpoint> {
        for endpoint in bootstrap_list {
            match transport::connect(endpoint) {
                Ok(trans) => {
                    let ep = trans.remote_endpoint.clone();
                    handle_connect(self.state.downgrade(), trans);
                    return Ok(ep)
                },
                Err(_)    => continue,
            }
        }
        // FIXME: The result should probably be Option<Endpoint>
        Err(io::Error::new(io::ErrorKind::Other, "No bootstrap node got connected"))
    }

    fn listen(&self, port: &Port) -> IoResult<Endpoint> {
        let acceptor = try!(transport::new_acceptor(port));
        let local_ep = try!(transport::local_endpoint(&acceptor));

        let mut weak_state = self.state.downgrade();

        let ep = local_ep.clone();
        try!(lock_mut_state(&mut weak_state, |s| Ok(s.listening_eps.insert(ep))));

        spawn(move || {
            loop {
                match transport::accept(&acceptor) {
                    Ok(trans) => {
                        let ws = weak_state.clone();
                        spawn(move || { let _ = handle_accept(ws, trans); });
                    },
                    Err(_) => {break},
                }
            }
        });

        Ok(local_ep)
    }
}

fn notify_user(state: &WeakState, event: Event) -> IoResult<()> {
    lock_state(state, |s| {
        s.event_pipe.send(event)
        .map_err(|_|io::Error::new(io::ErrorKind::BrokenPipe, "failed to notify_user"))
    })
}

fn lock_state<T, F: FnOnce(&State) -> IoResult<T>>(state: &WeakState, f: F) -> IoResult<T> {
    state.upgrade().ok_or(io::Error::new(io::ErrorKind::Interrupted,
                                         "Can't dereference weak"))
    .and_then(|arc_state| {
        let opt_state = arc_state.lock();
        match opt_state {
            Ok(s)  => f(&s),
            Err(e) => Err(io::Error::new(io::ErrorKind::Interrupted, "?"))
        }
    })
}

fn lock_mut_state<T, F: FnOnce(&mut State) -> IoResult<T>>(state: &WeakState, f: F) -> IoResult<T> {
    state.upgrade().ok_or(io::Error::new(io::ErrorKind::Interrupted,
                                         "Can't dereference weak"))
    .and_then(move |arc_state| {
        let opt_state = arc_state.lock();
        match opt_state {
            Ok(mut s)  => f(&mut s),
            Err(e) => Err(io::Error::new(io::ErrorKind::Interrupted, "?"))
        }
    })
}

fn handle_accept(mut state: WeakState, trans: transport::Transport) -> IoResult<Endpoint> {
    let remote_ep = trans.remote_endpoint.clone();
    register_connection(&mut state, trans, Event::NewConnection(remote_ep))
}

fn handle_connect(mut state: WeakState, trans: transport::Transport) -> IoResult<Endpoint> {
    let remote_ep = trans.remote_endpoint.clone();
    register_connection(&mut state, trans, Event::NewConnection(remote_ep))
}

fn register_connection( state: &mut WeakState,
                        trans: transport::Transport,
                        event_to_user: Event
                      ) -> IoResult<Endpoint> {

    let state2 = state.clone();

    lock_mut_state(state, move |s: &mut State| {
        let (tx, rx) = mpsc::channel();
        start_writing_thread(state2.clone(), trans.sender, trans.remote_endpoint.clone(), rx);
        start_reading_thread(state2, trans.receiver, trans.remote_endpoint.clone(), s.event_pipe.clone());
        s.connections.insert(trans.remote_endpoint.clone(), Connection{writer_channel: tx});
        let _ = s.event_pipe.send(event_to_user);
        Ok(trans.remote_endpoint)
    })
}

fn unregister_connection(state: WeakState, his_ep: Endpoint) {
    println!("unregister_connection");
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
                        sink: IoSender<Event>) {
    spawn(move || {
        loop {
            match transport::receive(&receiver) {
                Ok(msg) => if sink.send(Event::NewMessage(his_ep.clone(), msg)).is_err() {
                    break
                },
                Err(_) => break
            }
        }
        unregister_connection(state, his_ep);
    });
}

// pushing messages out to socket
fn start_writing_thread(state: WeakState,
                        mut o: transport::Sender,
                        his_ep: Endpoint,
                        writer_channel: mpsc::Receiver<Bytes>) {
    spawn(move || {
        for msg in writer_channel.iter() {
            if transport::send(&mut o, &msg).is_err() {
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
    use transport::{Port, Endpoint};
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
         listenig_end_point: Endpoint,
         connected_eps: Arc<Mutex<Vec<Endpoint>>>
     }

     #[derive(Debug)]
     struct Stats {
         new_connections_count: u32,
         messages_count: u32,
         lost_connection_count: u32
     }

     impl Node {
         pub fn new(cm: ConnectionManager, port: u16) -> (Node, Option<u16>) {
             let (end_points, beacon_port) =  cm.start_listening(vec![Port::Tcp(0)], Some(port)).unwrap();
             (Node { conn_mgr: cm, listenig_end_point: end_points[0].clone(), connected_eps: Arc::new(Mutex::new(Vec::new())) }, beacon_port)
         }
     }

     fn get_endpoint(node: &Arc<Mutex<Node>>) -> Endpoint {
         let node = node.clone();
         let node = node.lock().unwrap();
         node.listenig_end_point.clone()
     }

     fn get_connected_eps(node: &Arc<Mutex<Node>>) -> Vec<Endpoint> {
         let node = node.clone();
         let mut node = node.lock().unwrap();
         let eps = node.connected_eps.clone();
         let mut connected_eps = eps.lock().unwrap();
         connected_eps.clone()
     }

     struct Network {
         nodes: Vec<Arc<Mutex<Node>>>
     }

     impl Network {
         pub fn add(&mut self, beacon_port: u16) -> (Receiver<Event>, Endpoint, Option<u16>, Arc<Mutex<Vec<Endpoint>>>) {
             let (cm_i, cm_o) = channel();
             let (node, port) = Node::new(ConnectionManager::new(cm_i), beacon_port);
             let end_point = node.listenig_end_point.clone();
             let connected_eps = node.connected_eps.clone();
             self.nodes.push(Arc::new(Mutex::new(node)));
             (cm_o, end_point, port, connected_eps)
         }
     }

#[test]
    fn bootstrap() {
        let (cm1_i, _) = channel();
        let cm1 = ConnectionManager::new(cm1_i);
        let (cm1_eps, beacon_port) = cm1.start_listening(vec![Port::Tcp(0)], Some(0u16)).unwrap();

        thread::sleep_ms(1000);
        let (cm2_i, _) = channel();
        let cm2 = ConnectionManager::new(cm2_i);
        let (cm2_eps, beacon_port2) = cm2.start_listening(vec![Port::Tcp(0)], beacon_port.clone()).unwrap();
        match beacon_port2 {
            Some(_) => assert!(false, "should have been none"),
            None => assert!(true)
        };
        match cm2.bootstrap(None, beacon_port) {
            Ok(ep) => { assert_eq!(ep.clone(), cm1_eps[0].clone()); },
            Err(_) => { panic!("Failed to bootstrap"); }
        }
    }

#[test]
    fn connection_manager() {
        let run_cm = |cm: ConnectionManager, o: Receiver<Event>| {
            spawn(move || {
                for i in o.iter() {
                    match i {
                        Event::NewConnection(other_ep) => {
                            println!("Connected {:?}", other_ep);
                            let _ = cm.send(other_ep.clone(), encode(&"hello world".to_string()));
                        },
                        Event::NewMessage(from_ep, data) => {
                            println!("New message from {:?} data:{:?}",
                                     from_ep, decode::<String>(data));
                            break;
                        },
                        Event::LostConnection(other_ep) => {
                            println!("Lost connection to {:?}", other_ep);
                        }
                    }
                }
                println!("done");
            })
        };

        let (cm1_i, cm1_o) = channel();
        let cm1 = ConnectionManager::new(cm1_i);
        let (cm1_eps, beacon_port) = cm1.start_listening(vec![Port::Tcp(0)], Some(0u16)).unwrap();

        let (cm2_i, cm2_o) = channel();
        let cm2 = ConnectionManager::new(cm2_i);
        let (cm2_eps, _) = cm2.start_listening(vec![Port::Tcp(0)], beacon_port).unwrap();
        cm2.connect(cm1_eps.clone());
        cm1.connect(cm2_eps.clone());

        let runner1 = run_cm(cm1, cm1_o);
        let runner2 = run_cm(cm2, cm2_o);

        assert!(runner1.join().is_ok());
        assert!(runner2.join().is_ok());
    }

#[test]
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
                        Event::NewMessage(from_ep, data) => {
                            if count == MESSAGE_PER_NODE * (NETWORK_SIZE - 1) {
                                break;
                            }
                        },
                        Event::LostConnection(other_ep) => {
                        }
                    }
                }
                println!("done");
            })
        };

        let stats_accumulator = |stats: Arc<Mutex<Stats>>, stats_rx: Receiver<Event>|
            spawn(move || {
                for event in stats_rx.iter() {
                    let mut stat = stats.lock().unwrap();
                    match event {
                            Event::NewConnection(other_ep) => {
                            stat.new_connections_count += 1;
                        },
                        Event::NewMessage(from_ep, data) => {
                            let data_str = decode::<String>(data);
                            if data_str == "EXIT" {
                                break;
                            }
                            stat.messages_count += 1;
                            if stat.messages_count == NETWORK_SIZE * MESSAGE_PER_NODE * (NETWORK_SIZE - 1) {
                                break;
                            }
                        },
                        Event::LostConnection(other_ep) => {
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
        let (stats_tx, stats_rx): (Sender<Event>, Receiver<Event>) = channel();
        let mut runners = Vec::new();
        let mut beacon_port: u16 = 0;
        for index in 0..NETWORK_SIZE {
            let (receiver, end_point, port, connected_eps) = network.add(beacon_port);
            beacon_port = match port {
                Some(port_no) => port_no,
                None => beacon_port
            };
            let stat = Arc::new(Mutex::new(Stats {new_connections_count: 0, messages_count: 0,
                 lost_connection_count: 0} ));
            let stat_copy = stat.clone();
            let runner = run_cm(stats_tx.clone(), receiver, connected_eps);
            runners.push(runner);
        }

        let run_stats = stats_accumulator(stats.clone(), stats_rx);

        let mut listening_end_points = Vec::new();
            for node in network.nodes.iter() {
            listening_end_points.push(get_endpoint(node));
        }

        for node in network.nodes.iter() {
            for end_point in listening_end_points.iter().filter(|&ep| get_endpoint(node).ne(ep)) {
                let node = node.clone();
                let ep = end_point.clone();
                spawn(move || {
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
                    spawn(move || {
                        let node = node.lock().unwrap();
                        let _ = node.conn_mgr.send(ep.clone(), encode(&"MESSAGE".to_string()));
                    });
                }
            }
        }

        let terminate_runner = run_terminate(listening_end_points[0].clone(), stats_tx.clone());

        let _ = run_stats.join();

        for _ in 0..NETWORK_SIZE {
            network.nodes.remove(0);
        }

        let stats_copy = stats.clone();
        let stat = stats_copy.lock().unwrap();
        assert_eq!(stat.new_connections_count, NETWORK_SIZE * (NETWORK_SIZE - 1));
        assert_eq!(stat.messages_count,  NETWORK_SIZE * MESSAGE_PER_NODE * (NETWORK_SIZE - 1));
        assert_eq!(stat.lost_connection_count, 0);
    }
}
