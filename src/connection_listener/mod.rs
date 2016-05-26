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

mod exchange_msg;

use mio::{EventLoop, EventSet, PollOpt, Token};
use mio::tcp::TcpListener;
use sodiumoxide::crypto::box_::PublicKey;
use std::any::Any;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::rc::Rc;
use std::cell::RefCell;
use std::io;

use socket_addr;
use net2::TcpBuilder;
use self::exchange_msg::ExchangeMsg;
use core::{Core, State, Context};
use event::Event;
use nat::mapped_tcp_socket::MappingTcpSocket;
use nat::mapping_context::MappingContext;
use service::SharedConnectionMap;
use socket::Socket;
use static_contact_info::StaticContactInfo;

pub struct ConnectionListener {
    token: Token,
    context: Context,
    listener: TcpListener,
    cm: SharedConnectionMap,
    event_tx: ::CrustEventSender,
    name_hash: u64,
    our_pk: PublicKey,
}

impl ConnectionListener {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 port: u16,
                 our_pk: PublicKey,
                 name_hash: u64,
                 cm: SharedConnectionMap,
                 mapping_context: Arc<MappingContext>,
                 static_contact_info: Arc<Mutex<StaticContactInfo>>,
                 event_tx: ::CrustEventSender) {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        let event_tx_0 = event_tx.clone();

        match MappingTcpSocket::new(core,
                                    event_loop,
                                    &addr,
                                    &mapping_context,
                                    move |core, event_loop, socket, mapped_addrs| {
                                        match ConnectionListener::handle_mapped_socket(core,
                                                           event_loop,
                                                           socket,
                                                           mapped_addrs,
                                                           addr,
                                                           our_pk,
                                                           name_hash,
                                                           cm,
                                                           static_contact_info,
                                                           event_tx.clone()) {
                Ok(()) => (),
                Err(e) => {
                    error!("TCP Listener failed: {:?}", e);
                    let _ = event_tx.send(Event::ListenerFailed);
                }
            }
                                    }) {
            Ok(()) => {}
            Err(e) => {
                error!("Error starting tcp_listening_socket: {}", e);
                let _ = event_tx_0.send(Event::ListenerFailed);
            }
        }
    }

    fn handle_mapped_socket(core: &mut Core,
                            event_loop: &mut EventLoop<Core>,
                            socket: TcpBuilder,
                            mapped_addrs: Vec<socket_addr::SocketAddr>,
                            addr: SocketAddr,
                            our_pk: PublicKey,
                            name_hash: u64,
                            cm: SharedConnectionMap,
                            static_contact_info: Arc<Mutex<StaticContactInfo>>,
                            event_tx: ::CrustEventSender)
                            -> io::Result<()> {
        let token = core.get_new_token();
        let context = core.get_new_context();

        let listener = try!(socket.listen(1));
        let local_addr = try!(listener.local_addr());

        let listener = try!(TcpListener::from_listener(listener, &addr));
        try!(event_loop.register(&listener,
                                 token,
                                 EventSet::readable() | EventSet::error() | EventSet::hup(),
                                 PollOpt::edge()));

        static_contact_info.lock()
                           .unwrap()
                           .tcp_acceptors
                           .extend(mapped_addrs);

        let state = ConnectionListener {
            token: token,
            context: context,
            listener: listener,
            cm: cm,
            event_tx: event_tx.clone(),
            name_hash: name_hash,
            our_pk: our_pk,
        };

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));

        let _ = event_tx.send(Event::ListenerStarted(local_addr.port()));

        Ok(())
    }
}

impl State for ConnectionListener {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet) {
        if event_set.is_error() || event_set.is_hup() {
            self.terminate(core, event_loop);
        } else if event_set.is_readable() {
            match self.listener.accept() {
                Ok(Some((socket, _))) => {
                    if let Err(e) = ExchangeMsg::start(core,
                                                       event_loop,
                                                       Socket::wrap(socket),
                                                       self.our_pk.clone(),
                                                       self.name_hash,
                                                       self.cm.clone(),
                                                       self.event_tx.clone()) {
                        warn!("Error accepting direct connection: {:?}", e);
                    }
                }
                Ok(None) => (),
                Err(err) => error!("Failed to accept new socket: {:?}", err),
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = event_loop.deregister(&self.listener);
        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::exchange_msg::EXCHANGE_MSG_TIMEOUT_MS;

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

        let cm = Arc::new(Mutex::new(HashMap::new()));
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
                                        cm,
                                        mapping_context,
                                        our_static_contact_info,
                                        crust_sender);
          }))
          .expect("Could not send to tx");

        for it in event_rx.iter() {
            match it {
                Event::ListenerStarted(_port) => break,
                _ => panic!("Unexpected event notification - {:?}", it),
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
        let listener_addr = StdSocketAddr::new(listener.acceptor.ip(), listener.acceptor.port());
        TcpStream::connect(listener_addr).expect("Could not connect to listener")
    }

    fn client_send_request(stream: &mut TcpStream, message: Vec<u8>) -> io::Result<()> {
        let mut size_vec = Vec::with_capacity(4);
        unwrap_result!(size_vec.write_u32::<LittleEndian>(message.len() as u32));

        try!(stream.write_all(&size_vec));
        try!(stream.write_all(&message));
        Ok(())
    }

    #[test]
    fn connection_listener_bootstrap() {
        let listener = start_listener();
        let mut client = client_connect(&listener);
        let message = serialise(&Message::BootstrapRequest(box_::gen_keypair().0, 64)).unwrap();
        let _ = client_send_request(&mut client, message);

        for it in listener.event_rx.iter() {
            match it {
                Event::BootstrapAccept(_peer_id) => break,
                _ => panic!("Unexpected event notification"),
            }
        }
        listener.tx
                .send(CoreMessage::new(move |_, el| el.shutdown()))
                .expect("Could not shutdown el");
    }

    #[test]
    fn connection_listener_connect() {
        let listener = start_listener();
        let mut client = client_connect(&listener);
        let message = serialise(&Message::Connect(box_::gen_keypair().0, 64)).unwrap();
        let _ = client_send_request(&mut client, message);

        for it in listener.event_rx.iter() {
            match it {
                Event::NewPeer(_, _peer_id) => break,
                _ => panic!("Unexpected event notification - {:?}", it),
            }
        }
        listener.tx
                .send(CoreMessage::new(move |_, el| el.shutdown()))
                .expect("Could not shutdown el");
    }

    #[test]
    fn connection_listener_timeout() {
        let listener = start_listener();
        let mut client = client_connect(&listener);
        thread::sleep(Duration::from_millis(EXCHANGE_MSG_TIMEOUT_MS + 1000));

        let message = serialise(&Message::BootstrapRequest(box_::gen_keypair().0, 64)).unwrap();
        match client_send_request(&mut client, message) {
            Ok(_) => panic!("Unexpected success"),
            Err(_) => (),
        }
        listener.tx
                .send(CoreMessage::new(move |_, el| el.shutdown()))
                .expect("Could not shutdown el");
    }
}
