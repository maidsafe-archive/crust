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


use common::{self, Core, State};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use mio::{EventLoop, EventSet, PollOpt, Token};

use mio::udp::UdpSocket;
use rand;
use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;
use std::u16;

#[derive(RustcEncodable, RustcDecodable)]
enum DiscoveryMsg {
    Request { guid: u64 },
    Response(Vec<common::SocketAddr>),
}

pub struct ServiceDiscovery {
    token: Token,
    socket: UdpSocket,
    remote_addr: SocketAddr,
    listen: bool,
    read_buf: [u8; 1024],
    our_listeners: Arc<Mutex<Vec<SocketAddr>>>,
    seek_peers_req: Vec<u8>,
    reply_to: VecDeque<SocketAddr>,
    observers: Vec<Sender<Vec<common::SocketAddr>>>,
    guid: u64,
}

impl ServiceDiscovery {
    pub fn start(core: &mut Core,
                 el: &mut EventLoop<Core>,
                 our_listeners: Arc<Mutex<Vec<SocketAddr>>>,
                 token: Token,
                 port: u16)
                 -> Result<(), ServiceDiscoveryError> {
        let udp_socket = get_socket(port)?;
        udp_socket.set_broadcast(true)?;

        let guid = rand::random();
        let remote_addr = SocketAddr::from_str(&format!("255.255.255.255:{}", port))?;

        let service_discovery = ServiceDiscovery {
            token: token,
            socket: udp_socket,
            remote_addr: remote_addr,
            listen: false,
            read_buf: [0; 1024],
            our_listeners: our_listeners,
            seek_peers_req: serialise(&DiscoveryMsg::Request { guid: guid })?,
            reply_to: VecDeque::new(),
            observers: Vec::new(),
            guid: guid,
        };

        el.register(&service_discovery.socket,
                      token,
                      EventSet::error() | EventSet::hup() | EventSet::readable(),
                      PollOpt::edge())?;

        let _ = core.insert_state(token, Rc::new(RefCell::new(service_discovery)));

        Ok(())
    }

    /// Enable/disable listening and responding to peers searching for us. This will allow others
    /// finding us by interrogating the network.
    pub fn set_listen(&mut self, listen: bool) {
        self.listen = listen;
    }

    /// Interrogate the network to find peers.
    pub fn seek_peers(&mut self) -> Result<(), ServiceDiscoveryError> {
        let _ = self.socket.send_to(&self.seek_peers_req, &self.remote_addr)?;
        Ok(())
    }

    /// Register service discovery observer
    pub fn register_observer(&mut self, obs: Sender<Vec<common::SocketAddr>>) {
        self.observers.push(obs);
    }

    fn read(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        let (bytes_rxd, peer_addr) = match self.socket.recv_from(&mut self.read_buf) {
            Ok(Some((bytes_rxd, peer_addr))) => (bytes_rxd, peer_addr),
            Ok(None) => return,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => return,
            Err(e) => {
                warn!("ServiceDiscovery error in read: {:?}", e);
                self.terminate(core, el);
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
                    self.write(core, el)
                }
            }
            DiscoveryMsg::Response(peer_listeners) => {
                self.observers.retain(|obs| obs.send(peer_listeners.clone()).is_ok());
            }
        }
    }

    fn write(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        if let Err(e) = self.write_impl(el) {
            warn!("Error in ServiceDiscovery write: {:?}", e);
            self.terminate(core, el);
        }
    }

    fn write_impl(&mut self, el: &mut EventLoop<Core>) -> Result<(), ServiceDiscoveryError> {
        let our_current_listeners = unwrap!(self.our_listeners
                .lock())
            .iter()
            .map(|elt| common::SocketAddr(*elt))
            .collect();
        let resp = DiscoveryMsg::Response(our_current_listeners);

        let serialised_resp = serialise(&resp)?;

        if let Some(peer_addr) = self.reply_to.pop_front() {
            match self.socket.send_to(&serialised_resp[..], &peer_addr) {
                // UDP is all or none so if anything is written we consider it written
                Ok(Some(_)) => (),
                Ok(None) => self.reply_to.push_front(peer_addr),
                Err(ref e) if e.kind() == ErrorKind::Interrupted ||
                              e.kind() == ErrorKind::WouldBlock => {
                    self.reply_to
                        .push_front(peer_addr)
                }
                Err(e) => return Err(From::from(e)),
            }
        }

        let es = if self.reply_to.is_empty() {
            EventSet::error() | EventSet::hup() | EventSet::readable()
        } else {
            EventSet::error() | EventSet::hup() | EventSet::readable() | EventSet::writable()
        };

        Ok(el.reregister(&self.socket, self.token, es, PollOpt::edge())?)
    }
}

impl State for ServiceDiscovery {
    fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, es: EventSet) {
        if es.is_error() || es.is_hup() {
            self.terminate(core, el);
        } else {
            if es.is_readable() {
                self.read(core, el);
            }
            if es.is_writable() {
                self.write(core, el);
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        let _ = el.deregister(&self.socket);
        let _ = core.remove_state(self.token);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

fn get_socket(mut port: u16) -> Result<UdpSocket, ServiceDiscoveryError> {
    let mut res;
    loop {
        let bind_addr = SocketAddr::from_str(&format!("0.0.0.0:{}", port))?;
        let udp_socket = UdpSocket::v4()?;
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

    use common::{Core, CoreMessage};
    use maidsafe_utilities;
    use mio::{EventLoop, Token};

    use std::net;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use super::*;

    #[test]
    fn service_discovery() {
        // EventLoop-0
        let mut el0 = unwrap!(EventLoop::new(), "Could not spawn el0");
        let tx0 = el0.channel();
        let _raii_joiner_0 = maidsafe_utilities::thread::named("EL0", move || {
            unwrap!(el0.run(&mut Core::new()), "Could not run el0");
        });

        let addr = unwrap!(net::SocketAddr::from_str("138.139.140.150:54321"));
        let listeners_0 = Arc::new(Mutex::new(vec![addr]));
        let listeners_0_clone = listeners_0.clone();

        // ServiceDiscovery-0
        {
            let token_0 = Token(0);
            unwrap!(tx0.send(CoreMessage::new(move |core, el| {
                unwrap!(ServiceDiscovery::start(core, el, listeners_0_clone, token_0, 65530),
                        "Could not spawn ServiceDiscovery_0");
            })),
                    "Could not send to tx0");

            // Start listening for peers
            unwrap!(tx0.send(CoreMessage::new(move |core, _| {
                let state = unwrap!(core.get_state(token_0));
                let mut inner = state.borrow_mut();
                unwrap!(inner.as_any().downcast_mut::<ServiceDiscovery>()).set_listen(true);
            })));
        }

        thread::sleep(Duration::from_millis(100));

        // EventLoop-1
        let mut el1 = unwrap!(EventLoop::new(), "Could not spawn el1");
        let tx1 = el1.channel();
        let _raii_joiner_1 = maidsafe_utilities::thread::named("EL1", move || {
            unwrap!(el1.run(&mut Core::new()), "Could not run el1");
        });

        let (tx, rx) = mpsc::channel();

        // ServiceDiscovery-1
        {
            let listeners_1 = Arc::new(Mutex::new(vec![]));
            let token_1 = Token(0);
            unwrap!(tx1.send(CoreMessage::new(move |core, el| {
                        unwrap!(ServiceDiscovery::start(core, el, listeners_1, token_1, 65530),
                                "Could not spawn ServiceDiscovery_1");
                    })),
                    "Could not send to tx1");

            // Register observer
            unwrap!(tx1.send(CoreMessage::new(move |core, _| {
                let state = unwrap!(core.get_state(token_1));
                let mut inner = state.borrow_mut();
                unwrap!(inner.as_any()
                        .downcast_mut::<ServiceDiscovery>())
                    .register_observer(tx);
            })));

            // Seek peers
            unwrap!(tx1.send(CoreMessage::new(move |core, _| {
                        let state = unwrap!(core.get_state(token_1));
                        let mut inner = state.borrow_mut();
                        let sd = unwrap!(inner.as_any().downcast_mut::<ServiceDiscovery>());
                        unwrap!(sd.seek_peers());
                    })),
                    "Could not send to tx1");
        }

        let peer_listeners = unwrap!(rx.recv());
        assert_eq!(peer_listeners.into_iter().map(|elt| elt.0).collect::<Vec<_>>(),
                   *unwrap!(listeners_0.lock()));

        unwrap!(tx0.send(CoreMessage::new(move |_, el| el.shutdown())),
                "Could not shutdown el0");
        unwrap!(tx1.send(CoreMessage::new(move |_, el| el.shutdown())),
                "Could not shutdown el1");
    }
}
