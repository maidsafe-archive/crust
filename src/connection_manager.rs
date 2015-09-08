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
use std::sync::{Arc, mpsc, Mutex};
use std::sync::mpsc::Sender;
use std::thread;
use std::boxed::FnBox;

use beacon;
use bootstrap_handler::BootstrapHandler;
use config_handler::{Config, read_config_file};
use getifaddrs::{getifaddrs, filter_loopback};
use transport;
use transport::{Endpoint, Port, Message};

use asynchronous::{Deferred,ControlFlow};
use itertools::Itertools;
use map_external_port::map_external_port;
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
pub struct ConnectionManager {
    beacon_guid_and_port : Option<(beacon::GUID, u16)>,
    config               : Config,
    own_endpoints        : Vec<(Endpoint, Arc<Mutex<Option<Endpoint>>>)>,
    cmd_sender           : Sender<Closure>,
}

impl ConnectionManager {
    /// Constructs a connection manager. User needs to create an asynchronous channel, and provide
    /// the sender half to this method. Receiver will receive all `Event`s from this library.
    pub fn new(event_sender: mpsc::Sender<Event>) -> io::Result<ConnectionManager> {
        let config = read_config_file().unwrap_or_else(|e| {
            debug!("Crust failed to read config file; Error: {:?};", e);
            ::config_handler::create_default_config_file();
            let default = Config::make_default();
            debug!("Using default beacon_port {:?} and default bootstrapping methods enabled",
                default.beacon_port);
            default
        });

        ConnectionManager::construct(event_sender, config)
    }

    /// Construct a connection manager. As with the `ConnectionManager::new` function,
    /// but will not implicitly start any network activity. This construtor is intended
    /// only for testing purposes.
    pub fn new_inactive(event_sender: mpsc::Sender<Event>)
            -> io::Result<ConnectionManager> {
        ConnectionManager::construct(event_sender, Config::make_zero())
    }

    fn construct(event_sender: mpsc::Sender<Event>, config: Config)
            -> io::Result<ConnectionManager> {
        let tcp_listening_port = config.tcp_listening_port.clone();
        let utp_listening_port = config.utp_listening_port.clone();
        let beacon_port        = config.beacon_port.clone();

        let (cmd_sender, cmd_receiver) = mpsc::channel::<Closure>();

        let cmd_sender2 = cmd_sender.clone();

        let handle = try!(thread::Builder::new()
                            .name("ConnectionManager main loop".to_string())
                            .spawn(move || {
                                let mut state = State {
                                    event_sender : event_sender,
                                    cmd_sender : cmd_sender,
                                    connections : HashMap::new(),
                                    listening_ports: HashSet::new(),
                                    bootstrap_handler: None,
                                    stop_called: false,
                                    bootstrap_count: (0,0),
                                };

                                loop {
                                    match cmd_receiver.recv() {
                                        Ok(cmd) => cmd.call_box((&mut state,)),
                                        Err(_) => break,
                                    }
                                }
                            }));

        let mut cm = ConnectionManager { beacon_guid_and_port : None,
                                         config               : config,
                                         own_endpoints        : Vec::new(),
                                         cmd_sender           : cmd_sender2,
                                       };

        if let Some(port) = beacon_port {
            let _ = cm.start_broadcast_acceptor(port);
        }

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
        let acceptor = try!(transport::new_acceptor(port));
        let accept_port = acceptor.local_port();
        self.own_endpoints = map_external_port(&accept_port);

        Self::accept(self.cmd_sender.clone(), acceptor);

        if self.beacon_guid_and_port.is_some() {
            let contacts = filter_loopback(getifaddrs()).into_iter()
                .map(|ip| {
                    ::contact::Contact {
                        endpoint: Endpoint::new(ip.addr.clone(), accept_port)
                    }
                })
                .collect::<Vec<_>>();

            self.cmd_sender.send(Box::new(move |state : &mut State| {
                state.update_bootstrap_contacts(contacts);
            }));
        }

        Ok(accept_port)
    }

    fn start_broadcast_acceptor(&mut self, beacon_port: u16) -> io::Result<()> {
        let acceptor = try!(beacon::BroadcastAcceptor::new(beacon_port));

        // Right now we expect this function to succeed only once.
        assert!(self.beacon_guid_and_port.is_none());
        self.beacon_guid_and_port = Some((acceptor.beacon_guid(), acceptor.beacon_port()));

        let sender = self.cmd_sender.clone();

        self.cmd_sender.send(Box::new(move |state : &mut State| {
            assert!(state.bootstrap_handler.is_none());
            state.bootstrap_handler = Some(BootstrapHandler::new());

            let thread_result = thread::Builder::new()
                                .name("ConnectionManager beacon acceptor".to_string())
                                .spawn(move || {
                while let Ok(transport) = acceptor.accept() {
                    sender.send(Box::new(move |state : &mut State| {
                        state.respond_to_broadcast(transport);
                    }));
                }
            });

            // TODO: Handle gracefuly.
            assert!(thread_result.is_ok());
        }));

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
    /// Maximum of `max_successful_bootstrap_connection` bootstrap connections will be made and further connection
    /// attempts will stop.
    /// It will reiterate the list of all endpoints until it gets at least one connection.
    pub fn bootstrap(&mut self, max_successful_bootstrap_connection: usize) {
        let config = self.config.clone();
        let beacon_guid_and_port = self.beacon_guid_and_port.clone();

        self.cmd_sender.send(Box::new(move |state : &mut State| {
            // TODO: Review whether this is what we want (to disconnect
            // existing connections).
            let _ = state.connections.clear();
            state.bootstrap_count = (0, max_successful_bootstrap_connection.clone());

            let _ = thread::Builder::new().name("ConnectionManager bootstrap loop".to_string()).spawn(move || {
                //loop {
                //    let contacts = Self::populate_bootstrap_contacts(&config,
                //                                                     &beacon_guid_and_port,
                //                                                     ws.clone());
                //    match bootstrap_off_list(ws.clone(), contacts.clone(), beacon_guid_and_port.is_some(),
                //                             max_successful_bootstrap_connection) {
                //        Ok(_) => {
                //            debug!("Got at least one bootstrap connection. Breaking bootstrap loop.");
                //            break;
                //        },
                //        Err(_) => {
                //            // debug!("Failed to get at least one bootstrap connection. continuing bootstrap loop");
                //        }
                //    }
                //    // breaking the loop if stop called
                //    let weak_state_copy = ws.clone();
                //    let mut stop_called = false;
                //    {
                //        let _ = lock_mut_state(&weak_state_copy, |state: &mut State| {
                //            stop_called = state.stop_called;
                //            Ok(())
                //        });
                //    }
                //    if stop_called {
                //        break
                //    }
                //}
            });
        }));

    }

    /// This should be called before destroying an instance of a ConnectionManager to allow the
    /// listener threads to join.  Once called, the ConnectionManager should be destroyed.
    pub fn stop(&mut self) {
        if let Some(beacon_guid_and_port) = self.beacon_guid_and_port {
            beacon::BroadcastAcceptor::stop(&beacon_guid_and_port);
            self.beacon_guid_and_port = None;
        }
        // TODO
        //let mut listening_ports = Vec::<Port>::new();
        //let weak_state = Arc::downgrade(&self.state);
        //{
        //    let _ = lock_mut_state(&weak_state, |state: &mut State| {
        //        for itr in &state.listening_ports {
        //            listening_ports.push(itr.clone());
        //        }
        //        state.listening_ports.clear();
        //        state.stop_called = true;
        //        Ok(())
        //    });
        //}
        //// debug!("connection_manager::stop There are {} TCP ports being listened on", listening_ports.len());
        //for port in listening_ports {
        //    let ip_addr = IpAddr::V4(Ipv4Addr::new(127,0,0,1));
        //    let _ = transport::connect(Endpoint::new(ip_addr, port));
        //}
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

        self.cmd_sender.send(Box::new(move |state : &mut State| {
            for endpoint in &endpoints {
                if state.connections.contains_key(&endpoint) {
                    // TODO: User should be let know about this.
                    return;
                }
            }

            let cmd_sender = state.cmd_sender.clone();

            let _ = thread::Builder::new().name("ConnectionManager connect".to_string())
                                          .spawn(move || {
                for endpoint in endpoints {
                    if let Ok(transport) = transport::connect(endpoint) {
                        cmd_sender.send(Box::new(move |state: &mut State| {
                            state.handle_connect(transport, is_broadcast_acceptor, false);
                        }));
                        return;
                    }
                }
            });
        }));

    }

    /// Sends a message to specified address (endpoint). Returns Ok(()) if the sending might
    /// succeed, and returns an Err if the address is not connected. Return value of Ok does not
    /// mean that the data will be received. It is possible for the corresponding connection to hang
    /// up immediately after this function returns Ok.
    pub fn send(&self, endpoint: Endpoint, message: Bytes) -> io::Result<()> {
        self.cmd_sender.send(Box::new(move |state: &mut State| {
            let writer_channel = match state.connections.get(&endpoint) {
                Some(c) => c.writer_channel.clone(),
                None => {
                    // TODO: Generate async io::ErrorKind::NotConnected event
                    panic!();
                }
            };

            if let Err(what) = writer_channel.send(Message::UserBlob(message)) {
                // TODO: Generate async error event (BrokenPipe perhaps?).
                panic!();
            }
        }))
        .map_err(|_|io::Error::new(io::ErrorKind::BrokenPipe, "Main loop stoped"))
    }

    /// Closes connection with the specified endpoint.
    pub fn drop_node(&self, endpoint: Endpoint) {
        self.cmd_sender.send(Box::new(move |state: &mut State| {
            state.connections.remove(&endpoint);
        }));
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

    //fn listen(&mut self, port: Port) -> io::Result<Port> {
    //    let acceptor = try!(transport::new_acceptor(port));
    //    let local_port = acceptor.local_port();
    //    self.own_endpoints = map_external_port(&local_port);

    //    self.cmd_sender.send(Box::new(move |state| {
    //        state.listening_ports.insert(local_port);

    //        let _ = thread::Builder::new()
    //                .name("ConnectionManager listen".to_string())
    //                .spawn(move || {
    //            while let Ok(trans) = transport::accept(&acceptor) {
    //                let weak_state_copy = weak_state.clone();
    //                let mut stop_called = false;
    //                {
    //                    let _ = lock_mut_state(&weak_state_copy, |state: &mut State| {
    //                        stop_called = state.stop_called;
    //                        Ok(())
    //                    });
    //                }
    //                if stop_called {
    //                    break
    //                }
    //                self.cmd_sender.send(Box::new(move |state| {
    //                    let _ = state.handle_accept(trans);
    //                }));
    //            }
    //        });
    //    }));

    //    Ok(local_port)
    //}

    fn accept(cmd_sender: Sender<Closure>, acceptor: transport::Acceptor) {
        let cmd_sender2 = cmd_sender.clone();

        cmd_sender.send(Box::new(move |state: &mut State| {
            state.listening_ports.insert(acceptor.local_port());

            let _ = thread::Builder::new()
                    .name("ConnectionManager listen".to_string())
                    .spawn(move || {
                let accept_result = transport::accept(&acceptor);
                let cmd_sender3 = cmd_sender2.clone();

                cmd_sender2.send(Box::new(move |state: &mut State| {
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
        }));
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


// Returns Ok() if at least one connection succeeds
//fn bootstrap_off_list(weak_state: WeakState,
//                      bootstrap_list: ::contact::Contacts,
//                      is_broadcast_acceptor: bool,
//                      max_successful_bootstrap_connection: usize) -> io::Result<()> {
//    unimplemented!()
//    //let mut vec_deferred = vec![];
//
//    //for contact in bootstrap_list {
//    //    let ws = weak_state.clone();
//
//    //    let already_connected = try!(lock_state(&ws, |s| {
//    //        Ok(s.connections.contains_key(&contact.endpoint))
//    //    }));
//
//    //    if already_connected {
//    //        return Ok(())
//    //    }
//
//    //    vec_deferred.push(Deferred::new(move || {
//    //        match transport::connect(contact.endpoint.clone()) {
//    //            Ok(trans) => {
//    //                let ep = trans.remote_endpoint.clone();
//    //                let _ = try!(handle_connect(ws.clone(), trans,
//    //                                            is_broadcast_acceptor, true ));
//    //                return Ok(ep)
//    //            },
//    //            Err(e) => Err(e),
//    //        }
//    //    }));
//    //}
//    //let res = Deferred::first_to_promise(max_successful_bootstrap_connection,
//    //                                     false, vec_deferred,
//    //                                     ControlFlow::ParallelLimit(15))
//    //    .sync();
//    //let v = match res {
//    //    Ok(v) => v,
//    //    Err(v) => v.into_iter().filter_map(|e| e.ok()).collect(),
//    //};
//    //if v.len() > 0 {
//    //    Ok(())
//    //} else {
//    //    Err(io::Error::new(io::ErrorKind::Other,
//    //                       "No bootstrap node got connected"))
//    //}
//}

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
    use event::Event;

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

    //#[test]
    //fn bootstrap_off_list_connects() {
    //    let acceptor = transport::new_acceptor(Port::Tcp(0)).unwrap();
    //    let addr = match acceptor {
    //        transport::Acceptor::Tcp(_, listener) => listener.local_addr()
    //            .unwrap(),
    //        _ => panic!("Unable to create a new connection"),
    //    };
    //    let addr = match addr {
    //        SocketAddr::V4(a) => if a.ip().is_unspecified() {
    //            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1),
    //                                             a.port()))
    //        } else {
    //            SocketAddr::V4(a)
    //        },
    //        SocketAddr::V6(a) => if a.ip().is_unspecified() {
    //            SocketAddr::V6(SocketAddrV6::new("::1".parse().unwrap(),
    //                                             a.port(), a.flowinfo(),
    //                                             a.scope_id()))
    //        } else {
    //            SocketAddr::V6(a)
    //        },
    //    };
    //    let ep = Endpoint::Tcp(addr);
    //    let state = Arc::new(Mutex::new(super::State{ event_sender: channel().0,
    //                                                  connections: HashMap::new(),
    //                                                  listening_ports: HashSet::new(),
    //                                                  bootstrap_handler: None,
    //                                                  stop_called: false,
    //                                                  bootstrap_count: (0,1),
    //                                                }));
    //    assert!(super::bootstrap_off_list(Arc::downgrade(&state), vec![], false, 15).is_err());
    //    assert!(super::bootstrap_off_list(Arc::downgrade(&state),
    //                                      vec![::contact::Contact{endpoint: ep.clone()}], false, 15)
    //            .is_ok());
    //}

    //#[test]
    //fn bootstrap_off_list_connects_multiple() {
    //    let max_count = 4;
    //    let available_peer_count = 10;

    //    let mut contacts = vec![];
    //    let mut acceptors = vec![];
    //    loop {
    //        let acceptor = transport::new_acceptor(Port::Tcp(0)).unwrap();
    //        let addr = match acceptor {
    //            transport::Acceptor::Tcp(_, ref listener) => listener.local_addr()
    //                .unwrap(),
    //            _ => panic!("Unable to create a new connection"),
    //        };
    //        let addr = match addr {
    //            SocketAddr::V4(a) => if a.ip().is_unspecified() {
    //                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1),
    //                                                 a.port()))
    //            } else {
    //                SocketAddr::V4(a)
    //            },
    //            SocketAddr::V6(a) => if a.ip().is_unspecified() {
    //                SocketAddr::V6(SocketAddrV6::new("::1".parse().unwrap(),
    //                                                 a.port(), a.flowinfo(),
    //                                                 a.scope_id()))
    //            } else {
    //                SocketAddr::V6(a)
    //            },
    //        };
    //        contacts.push(::contact::Contact{endpoint: Endpoint::Tcp(addr)});
    //        acceptors.push(acceptor);
    //        if contacts.len() == available_peer_count {
    //            break;
    //        }
    //    }

    //    let (tx, rx) = channel();
    //    let state = Arc::new(Mutex::new(super::State{ event_sender: tx,
    //                                                  connections: HashMap::new(),
    //                                                  listening_ports: HashSet::new(),
    //                                                  bootstrap_handler: None,
    //                                                  stop_called: false,
    //                                                  bootstrap_count: (0,max_count),
    //                                                }));
    //    assert!(super::bootstrap_off_list(Arc::downgrade(&state), vec![], false, 15).is_err());
    //    assert!(super::bootstrap_off_list(Arc::downgrade(&state),
    //                                      contacts.clone(), false, max_count).is_ok());

    //    // read if rx gets max_count bootstrap eps
    //    let mut received_event_count = 0;
    //    while received_event_count < max_count {
    //        match rx.recv() {
    //            Ok(Event::NewBootstrapConnection(ep)) => {
    //                assert!(contacts.contains(&::contact::Contact{endpoint: ep}));
    //                received_event_count += 1;
    //            },
    //            _ => { panic!("Unexpected event !")},
    //        }
    //    }

    //    // should not get any more than max bs connections
    //    for _ in 0..10 {
    //        thread::sleep_ms(100);
    //        assert!(rx.try_recv().is_err());
    //    }
    //}
}
