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

use rand;
use std::u16;
use std::rc::Rc;
use std::any::Any;
use std::str::FromStr;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;
use std::collections::VecDeque;

use core::{Core, Context, State};
use static_contact_info::StaticContactInfo;
use maidsafe_utilities::serialisation::{serialise, deserialise};

use mio::udp::UdpSocket;
use mio::{Token, EventLoop, EventSet, PollOpt};

#[derive(RustcEncodable, RustcDecodable)]
enum DiscoveryMsg {
    Request {
        guid: u64,
    },
    Response(StaticContactInfo),
}

pub struct ServiceDiscovery {
    token: Token,
    socket: UdpSocket,
    remote_addr: SocketAddr,
    listen: bool,
    read_buf: [u8; 1024],
    static_contact_info: Arc<Mutex<StaticContactInfo>>,
    seek_peers_req: Vec<u8>,
    reply_to: VecDeque<SocketAddr>,
    observers: Vec<Sender<StaticContactInfo>>,
    guid: u64,
}

impl ServiceDiscovery {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 static_contact_info: Arc<Mutex<StaticContactInfo>>,
                 context: Context,
                 port: u16)
                 -> Result<(), ServiceDiscoveryError> {
        let token = core.get_new_token();

        let udp_socket = try!(get_socket(port));
        try!(udp_socket.set_broadcast(true));

        let guid = rand::random();
        let remote_addr = try!(SocketAddr::from_str(&format!("255.255.255.255:{}", port)));

        let service_discovery = ServiceDiscovery {
            token: token,
            socket: udp_socket,
            remote_addr: remote_addr,
            listen: false,
            read_buf: [0; 1024],
            static_contact_info: static_contact_info,
            seek_peers_req: try!(serialise(&DiscoveryMsg::Request { guid: guid })),
            reply_to: VecDeque::new(),
            observers: Vec::new(),
            guid: guid,
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

    /// Register service discovery observer
    pub fn register_observer(&mut self, obs: Sender<StaticContactInfo>) {
        self.observers.push(obs);
    }

    fn read(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let (bytes_rxd, peer_addr) = match self.socket.recv_from(&mut self.read_buf) {
            Ok(Some((bytes_rxd, peer_addr))) => (bytes_rxd, peer_addr),
            Ok(None) => return,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => return,
            Err(e) => {
                warn!("ServiceDiscovery error in read: {:?}", e);
                self.terminate(core, event_loop);
                return;
            }
        };

        let msg: DiscoveryMsg = match deserialise(&self.read_buf[..bytes_rxd]) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Bogus message serialisation error: {:?}", e);
                return;
            }
        };

        match msg {
            DiscoveryMsg::Request { guid } => {
                if self.listen && self.guid != guid {
                    self.reply_to.push_back(peer_addr);
                    self.write(core, event_loop)
                }
            }
            DiscoveryMsg::Response(peer_static_contact_info) => {
                self.observers.retain(|obs| obs.send(peer_static_contact_info.clone()).is_ok());
            }
        }
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Err(e) = self.write_impl(event_loop) {
            warn!("Error in ServiceDiscovery write: {:?}", e);
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
    fn ready(&mut self,
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
        if let Err(e) = event_loop.deregister(&self.socket) {
            warn!("Error deregistering ServiceDiscovery: {:?}", e);
        }
        if let Some(context) = core.remove_context(self.token) {
            let _ = core.remove_state(context);
        }
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

#[cfg(test)]
mod test {
    use super::*;

    use std::net;
    use socket_addr;
    use std::thread;
    use mio::EventLoop;
    use std::sync::mpsc;
    use std::str::FromStr;
    use std::time::Duration;
    use std::sync::{Arc, Mutex};
    use core::{CoreMessage, Core};
    use static_contact_info::StaticContactInfo;
    use maidsafe_utilities::thread::RaiiThreadJoiner;

    #[test]
    fn service_discovery() {
        // EventLoop-0
        let mut el0 = EventLoop::new().expect("Could not spawn el0");
        let tx0 = el0.channel();
        let _raii_joiner_0 = RaiiThreadJoiner::new(thread!("EL0", move || {
            el0.run(&mut Core::new()).expect("Could not run el0");
        }));

        let static_info_0 = Arc::new(Mutex::new(StaticContactInfo {
            tcp_acceptors: vec![socket_addr::SocketAddr(net::SocketAddr::from_str("138.139.140.\
                                                                                   150:54321")
                                    .expect("Could not parse address from string."))],
            tcp_mapper_servers: Vec::new(),
        }));
        let static_info_0_clone = static_info_0.clone();

        // ServiceDiscovery-0
        {
            let sd0 = Arc::new(Mutex::new(None));
            let sd0_clone = sd0.clone();
            tx0.send(CoreMessage::new(move |core, el| {
                    let context = core.get_new_context();
                    *sd0_clone.lock().unwrap() = Some(context);

                    ServiceDiscovery::start(core, el, static_info_0_clone, context, 65530)
                        .expect("Could not spawn ServiceDiscovery_0");
                }))
                .expect("Could not send to tx0");

            // Start listening for peers
            tx0.send(CoreMessage::new(move |core, _| {
                    let state = core.get_state(sd0.lock()
                            .unwrap()
                            .expect("ServiceDiscovery_0 hasn't registered a handle yet"))
                        .expect("State for SD0 hasn't been registered yet");
                    let mut inner = state.borrow_mut();
                    inner.as_any()
                        .downcast_mut::<ServiceDiscovery>()
                        .expect("Cast Failure")
                        .set_listen(true);
                }))
                .expect("Could not send to tx0");
        }

        thread::sleep(Duration::from_millis(100));

        // EventLoop-1
        let mut el1 = EventLoop::new().expect("Could not spawn el1");
        let tx1 = el1.channel();
        let _raii_joiner_1 = RaiiThreadJoiner::new(thread!("EL1", move || {
            el1.run(&mut Core::new()).expect("Could not run el1");
        }));

        let (tx, rx) = mpsc::channel();

        // ServiceDiscovery-1
        {
            let static_info_1 = Arc::new(Mutex::new(StaticContactInfo {
                tcp_acceptors: Vec::new(),
                tcp_mapper_servers: Vec::new(),
            }));
            let sd1 = Arc::new(Mutex::new(None));
            let sd1_clone = sd1.clone();
            tx1.send(CoreMessage::new(move |core, el| {
                    let context = core.get_new_context();
                    *sd1_clone.lock().unwrap() = Some(context);

                    ServiceDiscovery::start(core, el, static_info_1, context, 65530)
                        .expect("Could not spawn ServiceDiscovery_1");
                }))
                .expect("Could not send to tx1");

            // Register observer
            let sd1_clone = sd1.clone();
            tx1.send(CoreMessage::new(move |core, _| {
                    let state = core.get_state(sd1_clone.lock()
                            .unwrap()
                            .expect("ServiceDiscovery_1 hasn't registered a handle yet"))
                        .expect("State for SD1 hasn't been registered yet");
                    let mut inner = state.borrow_mut();
                    inner.as_any()
                        .downcast_mut::<ServiceDiscovery>()
                        .expect("Cast Failure")
                        .register_observer(tx);
                }))
                .expect("Could not send to tx1");

            // Seek peers
            tx1.send(CoreMessage::new(move |core, _| {
                    let state = core.get_state(sd1.lock()
                            .unwrap()
                            .expect("ServiceDiscovery_1 hasn't registered a handle yet"))
                        .expect("State for SD1 hasn't been registered yet");
                    let mut inner = state.borrow_mut();
                    inner.as_any()
                        .downcast_mut::<ServiceDiscovery>()
                        .expect("Cast Failure")
                        .seek_peers()
                        .expect("Failed setting seek_peers");
                }))
                .expect("Could not send to tx1");
        }

        let peer_static_info = rx.recv().unwrap();
        assert_eq!(peer_static_info, *static_info_0.lock().unwrap());

        tx0.send(CoreMessage::new(move |_, el| el.shutdown())).expect("Could not shutdown el0");
        tx1.send(CoreMessage::new(move |_, el| el.shutdown())).expect("Could not shutdown el1");
    }
}
