// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub use self::errors::ServiceDiscoveryError;

mod errors;

use common::{Core, State};
use mio::net::UdpSocket;
use mio::{Poll, PollOpt, Ready, Token};
use rand;
use socket_collection::UdpSock;
use std::any::Any;
use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::u16;

#[derive(Serialize, Deserialize)]
enum DiscoveryMsg {
    Request { guid: u64 },
    Response(Vec<SocketAddr>),
}

pub struct ServiceDiscovery {
    token: Token,
    socket: UdpSock,
    remote_addr: SocketAddr,
    listen: bool,
    our_listeners: Arc<Mutex<Vec<SocketAddr>>>,
    seek_peers_req: DiscoveryMsg,
    observers: Vec<Sender<Vec<SocketAddr>>>,
    guid: u64,
}

impl ServiceDiscovery {
    /// Starts service discovery process.
    ///
    /// # Args
    ///
    /// - listener_port - port we will be litening for incoming service discovery requests.
    /// - remote_port - port we will broadcasting service discovery requests to.
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        our_listeners: Arc<Mutex<Vec<SocketAddr>>>,
        token: Token,
        listener_port: u16,
        remote_port: u16,
    ) -> Result<(), ServiceDiscoveryError> {
        let udp_socket = UdpSocket::bind(&ipv4_addr(0, 0, 0, 0, listener_port))?;
        udp_socket.set_broadcast(true)?;
        let udp_socket = UdpSock::wrap(udp_socket);

        let guid = rand::random();
        let remote_addr = ipv4_addr(255, 255, 255, 255, remote_port);

        let service_discovery = ServiceDiscovery {
            token,
            socket: udp_socket,
            remote_addr,
            listen: false,
            our_listeners,
            seek_peers_req: DiscoveryMsg::Request { guid },
            observers: Vec::new(),
            guid,
        };

        poll.register(
            &service_discovery.socket,
            token,
            Ready::readable() | Ready::writable(),
            PollOpt::edge(),
        )?;

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
        let _ = self
            .socket
            .write_to(Some((&self.seek_peers_req, self.remote_addr, 0)))?;
        Ok(())
    }

    /// Register service discovery observer
    pub fn register_observer(&mut self, obs: Sender<Vec<SocketAddr>>) {
        self.observers.push(obs);
    }

    fn read(&mut self, core: &mut Core, poll: &Poll) {
        loop {
            match self.socket.read_frm() {
                Ok(Some((msg, peer_addr))) => {
                    self.handle_incoming_msg(msg, peer_addr);
                }
                Ok(None) => return,
                Err(e) => {
                    debug!("ServiceDiscovery error in read: {:?}", e);
                    self.terminate(core, poll);
                    return;
                }
            };
        }
    }

    fn handle_incoming_msg(&mut self, msg: DiscoveryMsg, peer_addr: SocketAddr) {
        match msg {
            DiscoveryMsg::Request { guid } => {
                if self.listen && self.guid != guid {
                    self.respond_with_their_addr(peer_addr);
                }
            }
            DiscoveryMsg::Response(peer_listeners) => {
                self.observers
                    .retain(|obs| obs.send(peer_listeners.clone()).is_ok());
            }
        }
    }

    fn write(&mut self, core: &mut Core, poll: &Poll) {
        match self.socket.write_to::<DiscoveryMsg>(None) {
            Ok(_) => (),
            Err(e) => {
                debug!("Failed to send response: {:?}", e);
                self.terminate(core, poll);
            }
        }
    }

    fn respond_with_their_addr(&mut self, peer_addr: SocketAddr) {
        let our_current_listeners = unwrap!(self.our_listeners.lock()).iter().cloned().collect();
        let resp = DiscoveryMsg::Response(our_current_listeners);
        match self.socket.write_to(Some((resp, peer_addr, 0))) {
            Ok(_) => (),
            Err(e) => debug!("Failed to send response: {:?}", e),
        }
    }
}

impl State for ServiceDiscovery {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_readable() {
            self.read(core, poll);
        }
        if kind.is_writable() {
            self.write(core, poll);
        }
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let _ = poll.deregister(&self.socket);
        let _ = core.remove_state(self.token);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

fn ipv4_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{self, CoreMessage};
    use mio::Token;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::{net, thread};

    #[test]
    fn service_discovery() {
        const SERVICE_DISCOVERY_TOKEN: usize = 0;

        // Poll-0
        let el0 = unwrap!(
            common::spawn_event_loop(SERVICE_DISCOVERY_TOKEN + 1, Some("EL0")),
            "Could not run el0"
        );

        let addr = unwrap!(net::SocketAddr::from_str("138.139.140.150:54321"));
        let listeners_0 = Arc::new(Mutex::new(vec![addr]));
        let listeners_0_clone = listeners_0.clone();

        // ServiceDiscovery-0
        {
            let token_0 = Token(SERVICE_DISCOVERY_TOKEN);
            unwrap!(
                el0.send(CoreMessage::new(move |core, poll| {
                    unwrap!(
                        ServiceDiscovery::start(
                            core,
                            poll,
                            listeners_0_clone,
                            token_0,
                            65_530,
                            65_530
                        ),
                        "Could not spawn ServiceDiscovery_0"
                    );
                })),
                "Could not send to el0"
            );

            // Start listening for peers
            unwrap!(el0.send(CoreMessage::new(move |core, _| {
                let state = unwrap!(core.get_state(token_0));
                let mut inner = state.borrow_mut();
                unwrap!(inner.as_any().downcast_mut::<ServiceDiscovery>()).set_listen(true);
            })));
        }

        thread::sleep(Duration::from_millis(100));

        // Poll-1
        let el1 = unwrap!(
            common::spawn_event_loop(SERVICE_DISCOVERY_TOKEN + 1, Some("EL1")),
            "Could not run el1"
        );

        let (tx, rx) = mpsc::channel();

        // ServiceDiscovery-1
        {
            let listeners_1 = Arc::new(Mutex::new(vec![]));
            let token_1 = Token(SERVICE_DISCOVERY_TOKEN);
            unwrap!(
                el1.send(CoreMessage::new(move |core, poll| {
                    unwrap!(
                        ServiceDiscovery::start(core, poll, listeners_1, token_1, 0, 65_530),
                        "Could not spawn ServiceDiscovery_1"
                    );
                })),
                "Could not send to el1"
            );

            // Register observer
            unwrap!(el1.send(CoreMessage::new(move |core, _| {
                let state = unwrap!(core.get_state(token_1));
                let mut inner = state.borrow_mut();
                unwrap!(inner.as_any().downcast_mut::<ServiceDiscovery>()).register_observer(tx);
            })));

            // Seek peers
            unwrap!(
                el1.send(CoreMessage::new(move |core, _| {
                    let state = unwrap!(core.get_state(token_1));
                    let mut inner = state.borrow_mut();
                    let sd = unwrap!(inner.as_any().downcast_mut::<ServiceDiscovery>());
                    unwrap!(sd.seek_peers());
                })),
                "Could not send to el1"
            );
        }

        let peer_listeners = unwrap!(rx.recv_timeout(Duration::from_secs(30)));
        assert_eq!(
            peer_listeners.into_iter().collect::<Vec<_>>(),
            *unwrap!(listeners_0.lock())
        );
    }
}
