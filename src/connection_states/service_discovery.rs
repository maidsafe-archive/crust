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

use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use core::{Core, Context};
use event::Event;
use maidsafe_utilities::serialisation::{serialise, deserialise};
use mio::{Token, EventLoop, EventSet, PollOpt};
use mio::udp::UdpSocket;
use static_contact_info::StaticContactInfo;
use state::State;

#[derive(RustcEncodable, RustcDecodable)]
enum DiscoveryMsg {
    Request,
    Response(StaticContactInfo),
}

#[derive(RustcEncodable, RustcDecodable)]
pub enum ServiceDiscoveryConfig {
    EnableServiceDiscovery,
    DisableServiceDiscovery,
    SeekPeers,
}

fn bind_to_socket(mut port: u16) -> (u16, UdpSocket) {
    loop {
        let bind_addr = ("0.0.0.0", port).to_socket_addrs().expect("Failed in converting to addr")
                                         .next().expect("Failed to parse socket address");
        let udp_socket = UdpSocket::v4().expect("Failed to get a UdpSocket");
        match udp_socket.bind(&bind_addr) {
            Ok(()) => {
                return (udp_socket.local_addr().expect("Failed get local_addr").port(), udp_socket);
            }
            Err(e) => {
                println!("Failed in binding address with error {:?}", e);
            }
        }
        port += 1;
    }
}

pub struct ServiceDiscovery {
    token: Token,
    _context: Context,
    socket: UdpSocket,
    routing_tx: ::CrustEventSender,
    _requested_port: u16,
    _bound_port: u16,

    seek_peers_on: SocketAddr,
    broadcast_listen: bool,
    read_buf: [u8; 1024],
    static_contact_info: Arc<Mutex<StaticContactInfo>>,
    serialised_seek_peers_request: Vec<u8>,
    reply_to: VecDeque<SocketAddr>,
}

impl ServiceDiscovery {
    pub fn new(core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               routing_tx: ::CrustEventSender,
               static_contact_info: Arc<Mutex<StaticContactInfo>>,
               port: u16) {
        let context = core.get_new_context();
        let token = core.get_new_token();

        let serialised_seek_peers_request =
            serialise::<DiscoveryMsg>(&DiscoveryMsg::Request)
                .expect("Serialisation Error. TODO: Improve this");

        let (bound_port, udp_socket) = bind_to_socket(port);
        udp_socket.set_broadcast(true).expect("Failed in setting broadcast");
        println!("listening on {}", bound_port);

        let seek_peers_on = SocketAddr::from_str(&format!("255.255.255.255:{}", port))
                                .expect("Failed in parsing SocketAddr from string");

        let service_discovery = ServiceDiscovery {
            token: token,
            _context: context.clone(),
            socket: udp_socket,
            routing_tx: routing_tx,
            _requested_port: port,
            _bound_port: bound_port,

            seek_peers_on: seek_peers_on,
            broadcast_listen: false,
            read_buf: [0; 1024],
            static_contact_info: static_contact_info,
            serialised_seek_peers_request: serialised_seek_peers_request,
            reply_to: VecDeque::new(),
        };
        event_loop.register(&service_discovery.socket,
                            token,
                            EventSet::error() | EventSet::hup(),
                            PollOpt::edge())
                  .expect("Could not re-register socket with EventLoop<Core>");

        let _ = core.insert_context(token, context.clone());
        let _ = core.insert_state(context, Rc::new(RefCell::new(service_discovery)));
    }

    /// Enable listening and responding to peers searching for us. This will allow others finding us
    /// by interrogating the network.
    pub fn enable_listen_for_peers(&mut self, _core: &mut Core, event_loop: &mut EventLoop<Core>) {
        self.broadcast_listen = true;
        event_loop.reregister(&self.socket,
                              self.token.clone(),
                              EventSet::readable() | EventSet::error() | EventSet::hup(),
                              PollOpt::edge())
                  .expect("Could not re-register socket with EventLoop<Core>");
    }

    /// Disable listening and responding to peers searching for us. This will disallow others from
    /// finding us by interrogating the network.
    pub fn disable_listen_for_peers(&mut self, _core: &mut Core, event_loop: &mut EventLoop<Core>) {
        self.broadcast_listen = false;
        event_loop.reregister(&self.socket,
                              self.token.clone(),
                              EventSet::error() | EventSet::hup(),
                              PollOpt::edge())
                  .expect("Could not re-register socket with EventLoop<Core>");
    }

    /// Interrogate the network to find peers.
    pub fn seek_peers(&mut self, _core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = self.socket.send_to(&self.serialised_seek_peers_request, &self.seek_peers_on);
        event_loop.reregister(&self.socket,
                              self.token.clone(),
                              EventSet::readable() | EventSet::error() | EventSet::hup(),
                              PollOpt::edge())
                  .expect("Could not re-register socket with EventLoop<Core>");
    }

    fn read(&mut self, _core: &mut Core, event_loop: &mut EventLoop<Core>, token: Token) {
        if let Some((bytes_read, peer_addr)) =
                self.socket.recv_from(&mut self.read_buf).expect("Failed in reading") {
            let msg: DiscoveryMsg = if let Ok(msg) = deserialise(&self.read_buf[..bytes_read]) {
                msg
            } else {
                return;
            };

            match msg {
                DiscoveryMsg::Request => {
                    if self.broadcast_listen {
                        self.reply_to.push_back(peer_addr);
                        event_loop.reregister(&self.socket,
                                              token,
                                              EventSet::writable(),
                                              PollOpt::edge())
                                  .expect("Could not re-register socket with EventLoop<Core>");

                    }
                }
                DiscoveryMsg::Response(content) => {
                    let _ = self.routing_tx.send(Event::NewPeer(content));
                }
            }
        }
    }

    fn write(&mut self, _core: &mut Core, event_loop: &mut EventLoop<Core>, token: Token) {
        let reply = DiscoveryMsg::Response(self.static_contact_info.lock()
                .expect("failed in locking static_contact_info").clone());
        let serialised_reply = serialise(&reply).expect("Failed to serialise reply");
        while let Some(peer_addr) = self.reply_to.pop_front() {
            let mut sent_bytes = 0;
            while sent_bytes != serialised_reply.len() {
                if let Some(bytes_tx) = self.socket
                                            .send_to(&serialised_reply[sent_bytes..],
                                                     &peer_addr).expect("failed in sending") {
                    sent_bytes += bytes_tx;
                } else {
                    return;
                }
            }
        }
        event_loop.reregister(&self.socket,
                              token,
                              EventSet::readable()| EventSet::error() | EventSet::hup(),
                              PollOpt::edge())
                  .expect("Could not re-register socket with EventLoop<Core>");
    }
}

impl State for ServiceDiscovery {
    fn execute(&mut self,
               core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               token: Token,
               event_set: EventSet) {
        assert_eq!(token, self.token);

        if event_set.is_error() {
            panic!("connection error");
            // let _ = routing_tx.send(Error - Could not connect);
        } else if event_set.is_hup() {
            self.terminate(core, event_loop);
        } else if event_set.is_readable() {
            self.read(core, event_loop, token);
        } else if event_set.is_writable() {
            self.write(core, event_loop, token);
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        println!("existing service discovery");
        event_loop.deregister(&self.socket).expect("Could not dereregister socket");
        let context = core.remove_context(&self.token).expect("Context not found");
        let _ = core.remove_state(&context).expect("State not found");
        let _ = self.routing_tx.send(Event::ServiceDiscoveryTerminated);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
