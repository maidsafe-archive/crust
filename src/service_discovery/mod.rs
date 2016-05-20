// Copyright 2016 MaidSafe.net limited.
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

pub use self::errors::ServiceDiscoveryError;

mod errors;

use std::u16;
use std::rc::Rc;
use std::any::Any;
use std::str::FromStr;
use std::io::ErrorKind;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

use state::State;
use event::Event;
use core::{Core, Context};
use static_contact_info::StaticContactInfo;
use maidsafe_utilities::serialisation::{serialise, deserialise};

use mio::udp::UdpSocket;
use mio::{Token, EventLoop, EventSet, PollOpt};

#[derive(RustcEncodable, RustcDecodable)]
enum DiscoveryMsg {
    Request,
    Response(StaticContactInfo),
}

pub struct ServiceDiscovery {
    token: Token,
    socket: UdpSocket,
    routing_tx: ::CrustEventSender,
    remote_addr: SocketAddr,
    listen: bool,
    read_buf: [u8; 1024],
    static_contact_info: Arc<Mutex<StaticContactInfo>>,
    seek_peers_req: Vec<u8>,
    reply_to: VecDeque<SocketAddr>,
}

impl ServiceDiscovery {
    pub fn new(core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               routing_tx: ::CrustEventSender,
               static_contact_info: Arc<Mutex<StaticContactInfo>>,
               service_discovery_handle: Arc<Mutex<Option<Context>>>,
               port: u16)
               -> Result<(), ServiceDiscoveryError> {
        let context = core.get_new_context();
        let token = core.get_new_token();
        *service_discovery_handle.lock().unwrap() = Some(context);

        let udp_socket = try!(get_socket(port));
        try!(udp_socket.set_broadcast(true));

        let remote_addr = try!(SocketAddr::from_str(&format!("255.255.255.255:{}", port)));

        let service_discovery = ServiceDiscovery {
            token: token,
            socket: udp_socket,
            routing_tx: routing_tx,
            remote_addr: remote_addr,
            listen: false,
            read_buf: [0; 1024],
            static_contact_info: static_contact_info,
            seek_peers_req: try!(serialise(&DiscoveryMsg::Request)),
            reply_to: VecDeque::new(),
        };

        try!(event_loop.register(&service_discovery.socket,
                                 service_discovery.token,
                                 EventSet::error() | EventSet::hup() | EventSet::readable(),
                                 PollOpt::edge()));

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(service_discovery)));

        Ok(())
    }

    /// Enable/disable listening and responding to peers searching for us. This will allow others
    /// finding us by interrogating the network.
    pub fn set_listen(&mut self, listen: bool) {
        self.listen = listen;
    }

    /// Interrogate the network to find peers.
    pub fn seek_peers(&mut self) -> Result<(), ServiceDiscoveryError> {
        let _ = try!(self.socket.send_to(&self.seek_peers_req, &self.remote_addr));
        Ok(())
    }

    fn read(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let (bytes_rxd, peer_addr) = match self.socket.recv_from(&mut self.read_buf) {
            Ok(Some((bytes_rxd, peer_addr))) => (bytes_rxd, peer_addr),
            Ok(None) => return,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => return,
            Err(e) => {
                println!("ServiceDiscovery error in read: {:?}", e);
                self.terminate(core, event_loop);
                return;
            }
        };

        let msg: DiscoveryMsg = match deserialise(&self.read_buf[..bytes_rxd]) {
            Ok(msg) => msg,
            Err(e) => {
                println!("Bogus message serialisation error: {:?}", e);
                return;
            }
        };

        match msg {
            DiscoveryMsg::Request => {
                if self.listen {
                    self.reply_to.push_back(peer_addr);
                    self.write(core, event_loop)
                }
            }
            DiscoveryMsg::Response(content) => {
                let _ = self.routing_tx.send(Event::NewPeer(content));
            }
        }
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Err(e) = self.write_impl(event_loop) {
            println!("Error in ServiceDiscovery write: {:?}", e);
            self.terminate(core, event_loop);
        }
    }

    fn write_impl(&mut self,
                  event_loop: &mut EventLoop<Core>)
                  -> Result<(), ServiceDiscoveryError> {
        let current_static_contact_info = self.static_contact_info.lock().unwrap().clone();
        let resp = DiscoveryMsg::Response(current_static_contact_info);

        let serialised_resp = try!(serialise(&resp));

        if let Some(peer_addr) = self.reply_to.pop_front() {
            match self.socket.send_to(&serialised_resp[..], &peer_addr) {
                // UDP is all or none so if anything is written we consider it written
                Ok(Some(_)) => (),
                Ok(None) => self.reply_to.push_front(peer_addr),
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {
                    self.reply_to
                        .push_front(peer_addr)
                }
                Err(e) => return Err(From::from(e)),
            }
        }

        let event_set = if self.reply_to.is_empty() {
            EventSet::error() | EventSet::hup() | EventSet::readable()
        } else {
            EventSet::error() | EventSet::hup() | EventSet::readable() | EventSet::writable()
        };

        Ok(try!(event_loop.reregister(&self.socket, self.token, event_set, PollOpt::edge())))
    }
}

impl State for ServiceDiscovery {
    fn execute(&mut self,
               core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               _: Token,
               event_set: EventSet) {
        if event_set.is_error() {
            self.terminate(core, event_loop);
        } else if event_set.is_hup() {
            self.terminate(core, event_loop);
        } else {
            if event_set.is_readable() {
                self.read(core, event_loop);
            }
            if event_set.is_writable() {
                self.write(core, event_loop);
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        println!("Exiting service discovery");
        if let Err(e) = event_loop.deregister(&self.socket) {
            println!("Error deregistering ServiceDiscovery: {:?}", e);
        }
        if let Some(context) = core.remove_context(&self.token) {
            let _ = core.remove_state(&context);
        }
        let _ = self.routing_tx.send(Event::ServiceDiscoveryTerminated);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

fn get_socket(mut port: u16) -> Result<UdpSocket, ServiceDiscoveryError> {
    let mut res;
    loop {
        let bind_addr = try!(SocketAddr::from_str(&format!("0.0.0.0:{}", port)));
        let udp_socket = try!(UdpSocket::v4());
        match udp_socket.bind(&bind_addr) {
            Ok(()) => {
                res = Ok(udp_socket);
                break;
            }
            Err(e) => {
                // println!("ServiceDiscovery failed binding to port {} with error {:?} ; trying \
                //           next port...",
                //          port,
                //          e);
                res = Err(From::from(e));
            }
        }
        if port == u16::MAX {
            break;
        }
        port += 1;
    }

    res
}
