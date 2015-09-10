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
use transport::{Endpoint, Port, Message};
use std::thread::JoinHandle;

use itertools::Itertools;
use event::Event;
use connection::Connection;

pub type Bytes = Vec<u8>;
pub type Closure = Box<FnBox(&mut State) + Send>;

pub struct State {
    pub event_sender      : Sender<Event>,
    pub cmd_sender        : Sender<Closure>,
    pub connections       : HashMap<Endpoint, Connection>,
    pub listening_ports   : HashSet<Port>,
    pub bootstrap_handler : Option<BootstrapHandler>,
    pub stop_called       : bool,
    pub bootstrap_count   : (usize, usize), // (current, max)
}

impl State {
    pub fn update_bootstrap_contacts(&mut self,
                                     new_contacts: Vec<Endpoint>) {
        if let Some(ref mut bs) = self.bootstrap_handler {
            // TODO: What was the second arg supposed to be?
            let _ = bs.update_contacts(new_contacts, Vec::<Endpoint>::new());
        }
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

    pub fn handle_connect(&mut self,
                          trans                   : transport::Transport,
                          is_broadcast_acceptor   : bool,
                          is_bootstrap_connection : bool) -> io::Result<Endpoint> {
        if is_bootstrap_connection {
            self.bootstrap_count.0 += 1;
        }
    
        let remote_ep = trans.remote_endpoint.clone();
        let event = match is_bootstrap_connection {
            true => Event::NewBootstrapConnection(remote_ep),
            false => Event::NewConnection(remote_ep)
        };
    
        let endpoint = self.register_connection(trans, event);
        if is_broadcast_acceptor {
            if let Ok(ref endpoint) = endpoint {
                let mut contacts = Vec::<Endpoint>::new();
                contacts.push(endpoint.clone());
                self.update_bootstrap_contacts(contacts);
            }
        }
        endpoint
    }

    fn register_connection(&mut self,
                           trans         : transport::Transport,
                           event_to_user : Event) -> io::Result<Endpoint> {
        if self.connections.contains_key(&trans.remote_endpoint) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Already connected"))
        }
        let (tx, rx) = mpsc::channel();
        self.start_writing_thread(trans.sender, trans.remote_endpoint.clone(), rx);
        self.start_reading_thread(trans.receiver, trans.remote_endpoint.clone());
        let _ = self.connections.insert(trans.remote_endpoint.clone(), Connection{writer_channel: tx});
        let _ = self.event_sender.send(event_to_user);
        Ok(trans.remote_endpoint)
    }

    // pushing messages out to socket
    fn start_writing_thread(&self, mut sender     : transport::Sender,
                                   his_ep         : Endpoint,
                                   writer_channel : Receiver<Message>) {
        let cmd_sender = self.cmd_sender.clone();

        let _ = Self::new_thread("writer", move || {
            for msg in writer_channel.iter() {
                if sender.send(&msg).is_err() {
                    break;
                }
            }
            let _ = cmd_sender.send(Box::new(move |state : &mut State| {
                state.unregister_connection(his_ep);
            }));
        });
    }

    // pushing events out to event_sender
    fn start_reading_thread(&self, receiver : transport::Receiver,
                                   his_ep   : Endpoint) {
        let cmd_sender = self.cmd_sender.clone();
        let sink       = self.event_sender.clone();

        let _ = Self::new_thread("reader", move || {
            while let Ok(msg) = receiver.receive() {
                if let Message::UserBlob(msg) = msg {
                    if sink.send(Event::NewMessage(his_ep.clone(), msg)).is_err() {
                        break
                    }
                }
            }
            let _ = cmd_sender.send(Box::new(move |state : &mut State| {
                state.unregister_connection(his_ep);
            }));
        });
    }

    fn unregister_connection(&mut self, his_ep: Endpoint) {
        if self.connections.remove(&his_ep).is_some() {
            // Only send the event if the connection was there
            // to avoid duplicate events.
            let _ = self.event_sender.send(Event::LostConnection(his_ep));
        }
    }

    pub fn handle_accept(&mut self, trans: transport::Transport) -> io::Result<Endpoint> {
        let remote_ep = trans.remote_endpoint.clone();
        self.register_connection(trans, Event::NewConnection(remote_ep))
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

    pub fn bootstrap_off_list(&self,
                              bootstrap_list: Vec<Endpoint>,
                              is_broadcast_acceptor: bool,
                              max_successful_bootstrap_connection: usize) {
        // TODO: This check seems to also happen in handle_connect
        for contact in bootstrap_list.iter() {
            if self.connections.contains_key(&contact) {
                // TODO: Let user know we're not going to fulfill his request.
                return;
            }
        }

        let event_sender = self.event_sender.clone();
        let cmd_sender   = self.cmd_sender.clone();

        let _ = Self::new_thread("bootstrap_off_list", move || {
            let mut vec_deferred = vec![];

            for contact in bootstrap_list.into_iter() {
                vec_deferred.push(Deferred::new(move || {
                    transport::connect(contact.clone())
                }))
            }

            let res = Deferred::first_to_promise(max_successful_bootstrap_connection,
                                                 false,
                                                 vec_deferred,
                                                 ControlFlow::ParallelLimit(15)).sync();

            let ts = match res {
                Ok(ts) => ts,
                Err(ts) => ts.into_iter().filter_map(|e|e.ok()).collect(),
            };

            let _ = cmd_sender.send(Box::new(move |state: &mut State| {
                for t in ts {
                    let e = t.remote_endpoint.clone();
                    if state.handle_connect(t, is_broadcast_acceptor, true).is_ok() {
                        let _ = event_sender.send(Event::NewBootstrapConnection(e));
                    }
                }
            }));
        });
    }

    fn new_thread<F,T>(name: &str, f: F) -> io::Result<JoinHandle<T>> 
            where F: FnOnce() -> T, F: Send + 'static, T: Send + 'static {
        thread::Builder::new().name("State::".to_string() + name)
                              .spawn(f)
    }
}


