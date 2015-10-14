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
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use std::thread;
use std::boxed::FnBox;
use asynchronous::{Deferred,ControlFlow};

use beacon;
use bootstrap_handler::BootstrapHandler;
use config_handler::Config;
use getifaddrs::{getifaddrs, filter_loopback};
use transport;
use transport::{Endpoint, Port, Message, Handshake};
use std::thread::JoinHandle;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

use itertools::Itertools;
use event::{Event, MappedUdpSocket};
use connection::Connection;
use sequence_number::SequenceNumber;

pub type Closure = Box<FnBox(&mut State) + Send>;

pub struct ConnectionData {
    message_sender: Sender<Message>,
    mapper_address: Option<SocketAddr>,
}

pub struct State {
    pub event_sender        : Sender<Event>,
    pub cmd_sender          : Sender<Closure>,
    pub cmd_receiver        : Receiver<Closure>,
    pub connections         : HashMap<Connection, ConnectionData>,
    pub listening_ports     : HashSet<Port>,
    pub bootstrap_handler   : Option<BootstrapHandler>,
    pub stop_called         : bool,
    pub is_bootstrapping    : bool,
    pub next_punch_sequence : SequenceNumber,
    pub our_mapper_port     : Option<u16>,
}

impl State {
    pub fn new(event_sender: Sender<Event>,
               our_mapper_port: Option<u16>) -> State {
        let (cmd_sender, cmd_receiver) = mpsc::channel::<Closure>();

        State {
            event_sender        : event_sender,
            cmd_sender          : cmd_sender,
            cmd_receiver        : cmd_receiver,
            connections         : HashMap::new(),
            listening_ports     : HashSet::new(),
            bootstrap_handler   : None,
            stop_called         : false,
            is_bootstrapping    : false,
            next_punch_sequence : SequenceNumber::new(::rand::random()),
            our_mapper_port     : our_mapper_port,
        }
    }

    pub fn run(&mut self) {
        let mut state = self;
        loop {
            match state.cmd_receiver.recv() {
                Ok(cmd) => cmd.call_box((&mut state,)),
                Err(_) => break,
            }
            if state.stop_called {
                break;
            }
        }
    }

    pub fn update_bootstrap_contacts(&mut self,
                                     new_contacts: Vec<Endpoint>) {
        if let Some(ref mut bs) = self.bootstrap_handler {
            // TODO: What was the second arg supposed to be?
            let _ = bs.update_contacts(new_contacts, Vec::<Endpoint>::new());
        }
    }

    pub fn get_accepting_endpoints(&self) -> Vec<Endpoint> {
        // FIXME: We should get real endpoints from the acceptors
        // not use 'unspecified' ips.
        let unspecified_ip = IpAddr::V4(Ipv4Addr::new(0,0,0,0));
        self.listening_ports.iter()
            .cloned()
            .map(|port| Endpoint::new(unspecified_ip, port))
            .collect()
    }

    pub fn respond_to_broadcast(&mut self,
                                mut transport: ::transport::Transport) {
        if let Some(ref mut handler) = self.bootstrap_handler {
            if let Ok(contacts) = handler.read_file() {
                let msg = Message::Contacts(contacts);
                let _ = transport.sender.send(&msg);
            }
        }
    }

    pub fn populate_bootstrap_contacts(&mut self,
                                       config: &Config,
                                       beacon_guid_and_port: &Option<([u8; 16], u16)>)
            -> Vec<Endpoint> {
        if config.override_default_bootstrap {
            return config.hard_coded_contacts.clone();
        }

        let cached_contacts = if beacon_guid_and_port.is_some() {
            // this node "owns" bootstrap file
            let mut contacts = Vec::<Endpoint>::new();
            if let Some(ref mut handler) = self.bootstrap_handler {
                contacts = handler.read_file().unwrap_or(vec![]);
            }
            contacts
        } else {
            vec![]
        };

        let beacon_guid = beacon_guid_and_port.map(|(guid, _)| guid);

        let beacon_discovery = match config.beacon_port {
            Some(port) => Self::seek_peers(beacon_guid, port),
            None => vec![]
        };

        let mut combined_contacts
            = beacon_discovery.into_iter()
            .chain(config.hard_coded_contacts.iter().cloned())
            .chain(cached_contacts.into_iter())
            .unique() // Remove duplicates
            .collect::<Vec<_>>();

        // remove own endpoints
        let own_listening_endpoint = self.get_listening_endpoint();
        combined_contacts.retain(|c| !own_listening_endpoint.contains(&c));
        combined_contacts
    }

    fn get_listening_endpoint(&self) -> Vec<Endpoint> {
        let listening_ports = self.listening_ports.iter().cloned().collect::<Vec<Port>>();

        let mut endpoints = Vec::<Endpoint>::new();
        for port in listening_ports {
            for ifaddr in filter_loopback(getifaddrs()) {
                endpoints.push(Endpoint::new(ifaddr.addr, port));
            }
        }
        endpoints
    }

    fn handle_handshake(handshake : Handshake,
                        mut trans : transport::Transport)
            -> io::Result<(Handshake, transport::Transport)> {
        let handshake_err = Err(io::Error::new(io::ErrorKind::Other,
                                               "handshake failed"));

        if let Err(_) = trans.sender.send_handshake(handshake) {
            return handshake_err
        }

        trans.receiver.receive_handshake()
                      .and_then(|handshake| Ok((handshake, trans)))
                      .or(handshake_err)
    }

    pub fn send(&mut self, connection: Connection, bytes: Vec<u8>) {
        let writer_channel = match self.connections.get(&connection) {
            Some(connection_data) => connection_data.message_sender.clone(),
            None => {
                // Connection already destroyed or never existed.
                return;
            }
        };

        if let Err(what) = writer_channel.send(Message::UserBlob(bytes)) {
            self.unregister_connection(connection);
        }
    }

    pub fn connect(handshake : Handshake,
                   remote_ep : Endpoint)
            -> io::Result<(Handshake, transport::Transport)> {
        Self::handle_handshake(handshake,
                               try!(transport::connect(remote_ep)))
    }

    pub fn accept(handshake : Handshake,
                  acceptor  : &transport::Acceptor)
            -> io::Result<(Handshake, transport::Transport)> {
        Self::handle_handshake(handshake, try!(transport::accept(acceptor)))
    }

    pub fn handle_connect(&mut self,
                          handshake             : Handshake,
                          trans                 : transport::Transport,
                          is_broadcast_acceptor : bool) -> io::Result<Connection> {
        let c = trans.connection_id.clone();
        let event = Event::OnConnect(c);

        let connection = self.register_connection(handshake, trans, event);
        if is_broadcast_acceptor {
            if let Ok(ref connection) = connection {
                let contacts = vec![connection.peer_endpoint()];
                self.update_bootstrap_contacts(contacts);
            }
        }
        connection
    }

    fn register_connection(&mut self,
                           handshake     : Handshake,
                           trans         : transport::Transport,
                           event_to_user : Event) -> io::Result<Connection> {
        let connection = trans.connection_id.clone();

        debug_assert!(!self.connections.contains_key(&connection));
        let (tx, rx) = mpsc::channel();

        let mapper_addr = handshake.mapper_port
            .map(|port| {
                let peer_addr = trans.connection_id.peer_endpoint().get_address();
                SocketAddr::new(peer_addr.ip(), port)
            });

        let connection_data = ConnectionData {
            message_sender: tx,
            mapper_address: mapper_addr,
        };

        // We need to insert the event into event_sender *before* the
        // reading thread starts. It is because the reading thread
        // also inserts events into the pipe and if done very quickly
        // they may be inserted in wrong order.
        let _ = self.connections.insert(connection, connection_data);
        let _ = self.event_sender.send(event_to_user);

        self.start_writing_thread(trans.sender, connection.clone(), rx);
        self.start_reading_thread(trans.receiver, connection.clone());

        Ok(trans.connection_id)
    }

    // pushing messages out to socket
    fn start_writing_thread(&self, mut sender     : transport::Sender,
                                   connection     : Connection,
                                   writer_channel : Receiver<Message>) {
        let cmd_sender = self.cmd_sender.clone();

        let _ = Self::new_thread("writer", move || {
            for msg in writer_channel.iter() {
                if sender.send(&msg).is_err() {
                    break;
                }
            }
            let _ = cmd_sender.send(Box::new(move |state : &mut State| {
                state.unregister_connection(connection);
            }));
        });
    }

    // pushing events out to event_sender
    fn start_reading_thread(&self, mut receiver : transport::Receiver,
                            connection : Connection) {
        let cmd_sender = self.cmd_sender.clone();
        let sink       = self.event_sender.clone();

        let _ = Self::new_thread("reader", move || {
            while let Ok(msg) = receiver.receive() {
                if let Message::UserBlob(msg) = msg {
                    if sink.send(Event::NewMessage(connection.clone(), msg)).is_err() {
                        break
                    }
                }
            }
            let _ = cmd_sender.send(Box::new(move |state : &mut State| {
                state.unregister_connection(connection);
            }));
        });
    }

    pub fn unregister_connection(&mut self, connection: Connection) {
        // Avoid sending duplicate LostConnection event.
        if self.connections.remove(&connection).is_none() {
            return;
        }

        let _ = self.event_sender.send(Event::LostConnection(connection));
    }

    pub fn handle_accept(&mut self,
                         handshake : Handshake,
                         trans     : transport::Transport)
            -> io::Result<Connection> {
        let c = trans.connection_id.clone();
        self.register_connection(handshake, trans, Event::OnAccept(c))
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
            let mut transport
                = match State::connect(Handshake::default(),
                                       transport::Endpoint::Tcp(peer)) {
                    Ok(pair) => pair.1,
                    Err(_) => continue,
                };
            let message = match transport.receiver.receive() {
                Ok(message) => message,
                Err(_) => {
                    continue
                },
            };
    
            match message {
                Message::Contacts(new_endpoints) => {
                    for ep in new_endpoints {
                        endpoints.push(ep);
                    }
                },
                _ => continue
            }
        }
    
        endpoints
    }

    pub fn bootstrap_off_list(&mut self,
                              mut bootstrap_list: Vec<Endpoint>,
                              is_broadcast_acceptor: bool) {
        if self.is_bootstrapping { return; }
        self.is_bootstrapping = true;

        bootstrap_list.retain(|e| !self.is_connected_to(e));

        if bootstrap_list.is_empty() {
            let _ = self.event_sender.send(Event::BootstrapFinished);
            return;
        }

        let event_sender = self.event_sender.clone();
        let cmd_sender   = self.cmd_sender.clone();
        let mapper_port  = self.our_mapper_port.clone();

        let _ = Self::new_thread("bootstrap_off_list", move || {
            let mut vec_deferred = vec![];

            // TODO (peterj) would be useful if bootstrap_list contained
            // information whether the peer was connected using beacon
            // or otherwise. If using beacon, we do not want to send
            // him our mapper_port (it would be of no use for him).
            for contact in bootstrap_list.iter() {
                let c = contact.clone();
                vec_deferred.push(Deferred::new(move || {
                    let h = Handshake { mapper_port: mapper_port };
                    Self::connect(h, c)
                }))
            }

            // TODO: Setting ParallelLimit to more than 1 makes the
            // below tests fail. Investigate why and how it can be
            // fixed.
            let res = Deferred::first_to_promise(1,
                                                 false,
                                                 vec_deferred,
                                                 ControlFlow::ParallelLimit(1)).sync();

            let ts = match res {
                Ok(ts) => ts,
                Err(ts) => ts.into_iter().filter_map(|e|e.ok()).collect(),
            };

            let _ = cmd_sender.send(Box::new(move |state: &mut State| {
                if !state.is_bootstrapping {
                    let _ = event_sender.send(Event::BootstrapFinished);
                    return;
                }

                state.is_bootstrapping = false;

                if ts.is_empty() {
                    let _ = event_sender.send(Event::BootstrapFinished);
                    return;
                }

                for t in ts {
                    let _ = state.handle_connect(t.0, t.1, is_broadcast_acceptor);
                }

                state.bootstrap_off_list(bootstrap_list, is_broadcast_acceptor);
            }));
        });
    }

    pub fn stop_bootstrap(&mut self) {
        self.is_bootstrapping = false;
    }

    pub fn stop(&mut self) {
        self.stop_called = true;
    }

    fn new_thread<F,T>(name: &str, f: F) -> io::Result<JoinHandle<T>> 
            where F: FnOnce() -> T, F: Send + 'static, T: Send + 'static {
        thread::Builder::new().name("State::".to_string() + name)
                              .spawn(f)
    }

    fn is_connected_to(&self, endpoint: &Endpoint) -> bool {
        for pair in self.connections.iter() {
            if pair.0.peer_endpoint() == *endpoint {
                return true;
            }
        }
        return false;
    }

    fn get_ordered_helping_nodes(&self) -> Vec<SocketAddr> {
        let mut addrs = self.connections.iter()
                            .filter_map(|pair| pair.1.mapper_address)
                            .collect::<Vec<_>>();

        addrs.sort_by(|&addr1, &addr2| {
            ::util::heuristic_geo_cmp(&addr1.ip(), &addr2.ip()).reverse()
        });

        addrs
    }

    pub fn get_mapped_udp_socket(&mut self, result_token: u32) {
        use ::hole_punching::blocking_get_mapped_udp_socket;

        let seq_id = self.next_punch_sequence.number();
        self.next_punch_sequence.increment();

        let event_sender = self.event_sender.clone();
        let helping_nodes = self.get_ordered_helping_nodes();

        let result_handle = Self::new_thread("map_udp", move || {
            let result = blocking_get_mapped_udp_socket(seq_id, helping_nodes);

            let result = match result {
                // TODO (peterj) use _rest
                Ok((socket, opt_mapped_addr, _rest)) => {
                    let addrs = opt_mapped_addr.into_iter().collect();
                    Ok((socket, addrs))
                },
                Err(what) => Err(what),
            };

            let _ = event_sender.send(
                Event::OnUdpSocketMapped(
                    MappedUdpSocket{
                        result_token: result_token,
                        result: result,
                    }));
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::thread;
    use std::net::SocketAddr;
    use std::sync::mpsc::channel;
    use transport::{Endpoint, Port, Acceptor, Handshake};
    use event::Event;
    use util;

    fn testable_endpoint(acceptor: &Acceptor) -> Endpoint {
        let addr = match acceptor {
            &Acceptor::Tcp(_, ref listener) => listener.local_addr()
                .unwrap(),
            _ => panic!("Unable to create a new connection"),
        };

        let addr = SocketAddr::new(util::loopback_if_unspecified(addr.ip()), addr.port());
        Endpoint::Tcp(addr)
    }

    fn test_bootstrap_off_list(n: u16) {
        let acceptors = (0..n).map(|_|Acceptor::new(Port::Tcp(0)).unwrap())
                              .collect::<Vec<_>>();

        let eps = acceptors.iter().map(|a|testable_endpoint(&a))
                                  .collect();

        let (event_sender, event_receiver) = channel();

        let mut s = State::new(event_sender, None);

        let cmd_sender = s.cmd_sender.clone();

        assert!(cmd_sender.send(Box::new(move |s: &mut State| {
            s.bootstrap_off_list(eps, false);
        })).is_ok());

        let accept_thread = thread::spawn(move || {
            for a in acceptors {
                assert!(State::accept(Handshake::default(), &a).is_ok())
            }
        });

        let t = thread::spawn(move || { s.run(); });

        let mut accept_count = 0;

        loop {
            match event_receiver.recv() {
                Ok(event) => {
                    match event {
                        Event::OnConnect(_) => {
                            accept_count += 1;
                            if accept_count == n {
                                assert!(cmd_sender.send(Box::new(move |s: &mut State| {
                                    s.stop();
                                })).is_ok());
                                break;
                            }
                        },
                        Event::LostConnection(_) => { },
                        Event::BootstrapFinished => { },
                        _ => {
                            panic!("Unexpected event {:?}", event);
                        }
                    }
                },
                Err(_) => { panic!("Error while receiving events"); }
            }
        }

        assert!(t.join().is_ok());
        assert!(accept_thread.join().is_ok());
    }

    #[test]
    fn bootstrap_off_list() {
        test_bootstrap_off_list(1);
        test_bootstrap_off_list(2);
        test_bootstrap_off_list(4);
        test_bootstrap_off_list(8);
    }
}
