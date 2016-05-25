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

mod accept_connection;

pub const BOOTSTRAP_TIMEOUT_MS: u64 = 60_000;

use mio::{EventLoop, EventSet, PollOpt, Token};
use mio::tcp::TcpListener;
use sodiumoxide::crypto::box_::PublicKey;
use std::any::Any;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use self::accept_connection::AcceptConnection;
use core::{Core, State};
use event::Event;
use nat::mapped_tcp_socket::MappingTcpSocket;
use nat::mapping_context::MappingContext;
use service::SharedConnectionMap;
use socket::Socket;
use static_contact_info::StaticContactInfo;

pub struct ConnectionListener {
    connection_map: SharedConnectionMap,
    event_tx: ::CrustEventSender,
    listener: TcpListener,
    name_hash: u64,
    our_public_key: PublicKey,
    token: Token,
}

impl ConnectionListener {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 port: u16,
                 our_public_key: PublicKey,
                 name_hash: u64,
                 connection_map: SharedConnectionMap,
                 mapping_context: Arc<MappingContext>,
                 static_contact_info: Arc<Mutex<StaticContactInfo>>,
                 event_tx: ::CrustEventSender) {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        let event_tx_clone = event_tx.clone();
        // let mapping_context_clone = mapping_context.clone();
        match MappingTcpSocket::new(core,
                                    event_loop,
                                    &addr,
                                    &mapping_context,
                                    move |core, event_loop, socket, addrs| {
                                        let context = core.get_new_context();
                                        let token = core.get_new_token();
                                        let listener = match socket.listen(1) {
                                            Ok(listener) => listener,
                                            Err(error) => {
                                                error!("Failed to bind TCP listener: {:?}", error);
                                                let _ = event_tx.send(Event::ListenerFailed);
                                                return;
                                            }
                                        };
                                        let local_addr = match listener.local_addr() {
                                            Ok(address) => address,
                                            Err(error) => {
                                                error!("Failed to retrieve local address from \
                                                        the TCP listener: {:?}",
                                                       error);
                                                let _ = event_tx.send(Event::ListenerFailed);
                                                return;
                                            }
                                        };
                                        let listener = TcpListener::from_listener(listener, &addr)
                                                           .expect("start listener error");
                                        event_loop.register(&listener,
                                                            token,
                                                            EventSet::readable() |
                                                            EventSet::error() |
                                                            EventSet::hup(),
                                                            PollOpt::edge())
                                                  .expect("register to event loop error");
                                        static_contact_info.lock()
                                                           .expect("Failed in locking \
                                                                    static_contact_info")
                                                           .tcp_acceptors
                                                           .extend(addrs);
                                        let _ = event_tx.send(Event::ListenerStarted(local_addr.port()));
                                        let _ = core.insert_context(token, context.clone());
                                        let _ = core.insert_state(context.clone(),
                                                                  ConnectionListener {
                                                                      connection_map:
                                                                          connection_map,
                                                                      event_tx: event_tx,
                                                                      listener: listener,
                                                                      name_hash: name_hash,
                                                                      our_public_key:
                                                                          our_public_key,
                                                                      token: token,
                                                                  });
                                    }) {
            Ok(()) => {}
            Err(e) => {
                debug!("Error start tcp_listening_socket: {}", e);
                let _ = event_tx_clone.send(Event::ListenerFailed);
            }
        }
    }

    fn handle_accept(&mut self,
                     core: &mut Core,
                     event_loop: &mut EventLoop<Core>,
                     socket: Socket) {
        AcceptConnection::start(core,
                                event_loop,
                                socket,
                                self.our_public_key.clone(),
                                self.name_hash,
                                self.connection_map.clone(),
                                self.event_tx.clone())
    }
}

impl State for ConnectionListener {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet) {
        assert_eq!(token, self.token);
        assert!(event_set.is_readable());

        match self.listener.accept() {
            Ok(Some((socket, _))) => self.handle_accept(core, event_loop, Socket::wrap(socket)),
            Ok(None) => (),
            Err(err) => error!("Failed to accept new socket: {:?}", err),
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::collections::HashMap;
    use std::io::{self, Write};
    use std::net::SocketAddr as StdSocketAddr;
    use std::net::TcpStream;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use std::sync::{Arc, Mutex};

    use byteorder::{WriteBytesExt, LittleEndian};
    use core::{CoreMessage, Core};
    use event::Event;
    use maidsafe_utilities::event_sender::MaidSafeEventCategory;
    use maidsafe_utilities::serialisation::serialise;
    use maidsafe_utilities::thread::RaiiThreadJoiner;
    use message::Message;
    use mio::{EventLoop, Sender};
    use nat::mapping_context::MappingContext;
    use socket_addr::SocketAddr;
    use sodiumoxide::crypto::box_;
    use static_contact_info::StaticContactInfo;

    struct Listener {
        tx: Sender<CoreMessage>,
        _joiner: RaiiThreadJoiner,
        acceptor: SocketAddr,
        event_rx: mpsc::Receiver<Event>,
    }

    fn start_listener() -> Listener {
        let mut el = EventLoop::new().expect("Could not spawn el");
        let tx = el.channel();
        let raii_joiner = RaiiThreadJoiner::new(thread!("EL", move || {
            el.run(&mut Core::new()).expect("Could not run el");
        }));

        let (event_tx, event_rx) = mpsc::channel();
        let crust_sender = ::CrustEventSender::new(event_tx,
                                                   MaidSafeEventCategory::Crust,
                                                   mpsc::channel().0);

        let connection_map = Arc::new(Mutex::new(HashMap::new()));
        let mapping_context = Arc::new(MappingContext::new());
        let static_contact_info = Arc::new(Mutex::new(StaticContactInfo {
            tcp_acceptors: Vec::new(),
            tcp_mapper_servers: Vec::new(),
        }));
        let our_static_contact_info = static_contact_info.clone();

        tx.send(CoreMessage::new(move |core, el| {
              ConnectionListener::start(core,
                                        el,
                                        0,
                                        box_::gen_keypair().0,
                                        64,
                                        connection_map,
                                        mapping_context,
                                        our_static_contact_info,
                                        crust_sender);
          }))
          .expect("Could not send to tx");

        for it in event_rx.iter() {
            match it {
                Event::ListenerStarted(_port) => break,
                _ => panic!("Unexpected event notification"),
            }
        }
        let acceptor = static_contact_info.lock()
                                          .expect("Failed in locking static_contact_info")
                                          .tcp_acceptors[0];
        Listener {
            tx: tx,
            _joiner: raii_joiner,
            acceptor: acceptor,
            event_rx: event_rx,
        }
    }

    fn client_connect(listener: &Listener) -> TcpStream {
        TcpStream::connect(StdSocketAddr::new(listener.acceptor.ip(),
                                              listener.acceptor.port()))
                             .unwrap()
    }

    fn client_send_request(stream: &mut TcpStream) -> io::Result<()> {
        let message = serialise(&Message::BootstrapRequest(box_::gen_keypair().0, 64)).unwrap();
        let mut size_vec = Vec::with_capacity(4);
        unwrap_result!(size_vec.write_u32::<LittleEndian>(message.len() as u32));

        try!(stream.write_all(&size_vec));
        try!(stream.write_all(&message));
        Ok(())
    }

    #[test]
    fn connection_listener_connect() {
        let listener = start_listener();
        let mut client = client_connect(&listener);
        let _ = client_send_request(&mut client);

        for it in listener.event_rx.iter() {
            match it {
                Event::BootstrapAccept(_peer_id) => break,
                _ => panic!("Unexpected event notification"),
            }
        }
        listener.tx.send(CoreMessage::new(move |_, el| el.shutdown()))
                   .expect("Could not shutdown el");
    }

    #[test]
    fn connection_listener_timeout() {
        let listener = start_listener();
        let mut client = client_connect(&listener);
        thread::sleep(Duration::from_millis(BOOTSTRAP_TIMEOUT_MS + 1000));

        match client_send_request(&mut client) {
            Ok(_) => panic!("Unexpected success"),
            Err(_) => (),
        }
        listener.tx.send(CoreMessage::new(move |_, el| el.shutdown()))
                   .expect("Could not shutdown el");
    }
}
