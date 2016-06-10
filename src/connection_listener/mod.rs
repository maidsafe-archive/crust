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
use net2::TcpBuilder;
use socket_addr;
use sodiumoxide::crypto::box_::PublicKey;
use std::any::Any;
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use self::exchange_msg::ExchangeMsg;
use service::{ConnectionMap, NameHash};
use core::{Context, Core, State};
use event::Event;
use nat::mapped_tcp_socket::MappingTcpSocket;
use nat::mapping_context::MappingContext;
use socket::Socket;
use static_contact_info::StaticContactInfo;

const LISTENER_BACKLOG: i32 = 100;

pub struct ConnectionListener {
    cm: ConnectionMap,
    context: Context,
    event_tx: ::CrustEventSender,
    listener: TcpListener,
    name_hash: NameHash,
    our_pk: PublicKey,
    token: Token,
    timeout_ms: Option<u64>,
}

impl ConnectionListener {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 handshake_timeout_ms: Option<u64>,
                 port: u16,
                 our_pk: PublicKey,
                 name_hash: NameHash,
                 cm: ConnectionMap,
                 mapping_context: Arc<MappingContext>,
                 static_contact_info: Arc<Mutex<StaticContactInfo>>,
                 event_tx: ::CrustEventSender) {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        let event_tx_0 = event_tx.clone();

        let finish = move |core: &mut Core, el: &mut EventLoop<Core>, socket, mapped_addrs| {
            if let Err(e) = ConnectionListener::handle_mapped_socket(core,
                                                                     el,
                                                                     handshake_timeout_ms,
                                                                     socket,
                                                                     mapped_addrs,
                                                                     addr,
                                                                     our_pk,
                                                                     name_hash,
                                                                     cm,
                                                                     static_contact_info,
                                                                     event_tx.clone()) {
                error!("TCP Listener failed to handle mapped socket: {:?}", e);
                let _ = event_tx.send(Event::ListenerFailed);
            }
        };

        if let Err(e) = MappingTcpSocket::new(core, event_loop, &addr, &mapping_context, finish) {
            error!("Error starting tcp_listening_socket: {:?}", e);
            let _ = event_tx_0.send(Event::ListenerFailed);
        }
    }

    fn handle_mapped_socket(core: &mut Core,
                            event_loop: &mut EventLoop<Core>,
                            timeout_ms: Option<u64>,
                            socket: TcpBuilder,
                            mapped_addrs: Vec<socket_addr::SocketAddr>,
                            addr: SocketAddr,
                            our_pk: PublicKey,
                            name_hash: NameHash,
                            cm: ConnectionMap,
                            static_contact_info: Arc<Mutex<StaticContactInfo>>,
                            event_tx: ::CrustEventSender)
                            -> ::Res<()> {
        let token = core.get_new_token();
        let context = core.get_new_context();

        let listener = try!(socket.listen(LISTENER_BACKLOG));
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
            cm: cm,
            context: context,
            event_tx: event_tx.clone(),
            listener: listener,
            name_hash: name_hash,
            our_pk: our_pk,
            token: token,
            timeout_ms: timeout_ms,
        };

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));

        let _ = event_tx.send(Event::ListenerStarted(local_addr.port()));

        Ok(())
    }

    fn accept(&self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        loop {
            match self.listener.accept() {
                Ok(Some((socket, _))) => {
                    if let Err(e) = ExchangeMsg::start(core,
                                                       event_loop,
                                                       self.timeout_ms.clone(),
                                                       Socket::wrap(socket),
                                                       self.our_pk,
                                                       self.name_hash,
                                                       self.cm.clone(),
                                                       self.event_tx.clone()) {
                        warn!("Error accepting direct connection: {:?}", e);
                    }
                }
                Ok(None) => return,
                Err(err) => {
                    warn!("Failed to accept new socket: {:?}", err);
                    return;
                }
            }
        }
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
            let _ = self.event_tx.send(Event::ListenerFailed);
        } else if event_set.is_readable() {
            self.accept(core, event_loop);
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

    use std::mem;
    use std::sync::mpsc;
    use std::net::TcpStream;
    use std::time::Duration;
    use std::sync::{Arc, Mutex};
    use std::collections::HashMap;
    use std::io::{Cursor, Read, Write};
    use std::net::SocketAddr as StdSocketAddr;

    use event::Event;
    use message::Message;
    use socket_addr::SocketAddr;
    use mio::{EventLoop, Sender};
    use core::{Core, CoreMessage};
    use rustc_serialize::Decodable;
    use nat::mapping_context::MappingContext;
    use static_contact_info::StaticContactInfo;
    use sodiumoxide::crypto::box_::{self, PublicKey};
    use maidsafe_utilities::thread::RaiiThreadJoiner;
    use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
    use maidsafe_utilities::event_sender::MaidSafeEventCategory;
    use maidsafe_utilities::serialisation::{deserialise, serialise};

    type NameHash = u64;
    const NAME_HASH: NameHash = 9876543210;

    struct Listener {
        tx: Sender<CoreMessage>,
        pk: PublicKey,
        acceptor: SocketAddr,
        event_rx: mpsc::Receiver<Event>,
        _raii_joiner: RaiiThreadJoiner,
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            self.tx
                .send(CoreMessage::new(|_, el| el.shutdown()))
                .expect("Could not send shutdown to event_loop");
        }
    }

    fn start_listener() -> Listener {
        let mut el = EventLoop::new().expect("Could not spawn el");
        let tx = el.channel();
        let raii_joiner = RaiiThreadJoiner::new(thread!("EL", move || {
            el.run(&mut Core::new()).expect("Could not run el");
        }));

        let (event_tx, event_rx) = mpsc::channel();
        let crust_sender =
            ::CrustEventSender::new(event_tx, MaidSafeEventCategory::Crust, mpsc::channel().0);

        let cm = Arc::new(Mutex::new(HashMap::new()));
        let mapping_context = Arc::new(MappingContext::new());
        let static_contact_info = Arc::new(Mutex::new(StaticContactInfo {
            tcp_acceptors: Vec::new(),
            tcp_mapper_servers: Vec::new(),
        }));

        let our_static_contact_info = static_contact_info.clone();
        let (pk, _) = box_::gen_keypair();
        tx.send(CoreMessage::new(move |core, el| {
                ConnectionListener::start(core,
                                          el,
                                          Some(5000),
                                          0,
                                          pk,
                                          NAME_HASH,
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
            .expect("Failed to lock static_contact_info")
            .tcp_acceptors[0];

        Listener {
            tx: tx,
            pk: pk,
            acceptor: acceptor,
            event_rx: event_rx,
            _raii_joiner: raii_joiner,
        }
    }

    fn connect_to_listener(listener: &Listener) -> TcpStream {
        let listener_addr = StdSocketAddr::new(listener.acceptor.ip(), listener.acceptor.port());
        let stream = TcpStream::connect(listener_addr).expect("Could not connect to listener");
        stream.set_read_timeout(Some(Duration::from_millis(EXCHANGE_MSG_TIMEOUT_MS + 1000)))
            .expect("Could not set read timeout.");

        stream
    }

    fn write(stream: &mut TcpStream, message: Vec<u8>) -> ::Res<()> {
        let mut size_vec = Vec::with_capacity(mem::size_of::<u32>());
        unwrap_result!(size_vec.write_u32::<LittleEndian>(message.len() as u32));

        try!(stream.write_all(&size_vec));
        try!(stream.write_all(&message));

        Ok(())
    }

    #[allow(unsafe_code)]
    fn read<T: Decodable>(stream: &mut TcpStream) -> ::Res<T> {
        let mut payload_size_buffer = [0; 4];
        try!(stream.read_exact(&mut payload_size_buffer));

        let payload_size = try!(Cursor::new(&payload_size_buffer[..])
            .read_u32::<LittleEndian>()) as usize;

        let mut payload = Vec::with_capacity(payload_size);
        unsafe {
            payload.set_len(payload_size);
        }
        try!(stream.read_exact(&mut payload));

        Ok(deserialise(&payload).expect("Could not deserialise."))
    }

    fn bootstrap(name_hash: NameHash, pk: PublicKey, listener: Listener) {
        let mut us = connect_to_listener(&listener);

        let message = serialise(&Message::BootstrapRequest(pk, name_hash)).unwrap();
        write(&mut us, message).expect("Could not write.");

        match read(&mut us).expect("Could not read.") {
            Message::BootstrapResponse(peer_pk) => assert_eq!(peer_pk, listener.pk),
            msg => panic!("Unexpected message: {:?}", msg),
        }

        match listener.event_rx.recv().expect("Could not read event channel") {
            Event::BootstrapAccept(peer_id) => assert_eq!(peer_id, ::peer_id::new(pk)),
            event => panic!("Unexpected event notification: {:?}", event),
        }
    }

    fn connect(name_hash: NameHash, pk: PublicKey, listener: Listener) {
        let mut us = connect_to_listener(&listener);

        let message = serialise(&Message::Connect(pk, name_hash)).unwrap();
        write(&mut us, message).expect("Could not write.");

        let our_id = ::peer_id::new(pk);
        let their_id = match read(&mut us).expect("Could not read.") {
            Message::Connect(peer_pk, peer_hash) => {
                assert_eq!(peer_pk, listener.pk);
                assert_eq!(peer_hash, NAME_HASH);
                ::peer_id::new(peer_pk)
            }
            msg => panic!("Unexpected message: {:?}", msg),
        };

        if our_id > their_id {
            let message = serialise(&Message::ChooseConnection).unwrap();
            write(&mut us, message).expect("Could not write.");
        }

        match listener.event_rx.recv().expect("Could not read event channel") {
            Event::NewPeer(res, peer_id) => {
                assert_eq!(peer_id, ::peer_id::new(pk));
                assert!(res.is_ok());
            }
            event => panic!("Unexpected event notification: {:?}", event),
        }
    }

    #[test]
    fn bootstrap_with_correct_parameters() {
        let listener = start_listener();
        let (pk, _) = box_::gen_keypair();
        bootstrap(NAME_HASH, pk, listener);
    }

    #[test]
    fn connect_with_correct_parameters() {
        let listener = start_listener();
        let (pk, _) = box_::gen_keypair();
        connect(NAME_HASH, pk, listener);
    }

    #[test]
    #[should_panic]
    fn bootstrap_with_invalid_version_hash() {
        let listener = start_listener();
        let (pk, _) = box_::gen_keypair();
        bootstrap(NAME_HASH - 1, pk, listener);
    }

    #[test]
    #[should_panic]
    fn connect_with_invalid_version_hash() {
        let listener = start_listener();
        let (pk, _) = box_::gen_keypair();
        connect(NAME_HASH - 1, pk, listener);
    }

    #[test]
    #[should_panic]
    fn bootstrap_with_invalid_pub_key() {
        let listener = start_listener();
        bootstrap(NAME_HASH, listener.pk, listener);
    }

    #[test]
    #[should_panic]
    fn connect_with_invalid_pub_key() {
        let listener = start_listener();
        connect(NAME_HASH, listener.pk, listener);
    }

    #[test]
    fn invalid_msg_exchange() {
        let listener = start_listener();
        let mut us = connect_to_listener(&listener);

        let message = serialise(&Message::Heartbeat).unwrap();
        write(&mut us, message).expect("Could not write.");

        let mut buf = [0; 512];
        if cfg!(windows) {
            assert!(us.read(&mut buf).is_err());
        } else {
            assert_eq!(0,
                       us.read(&mut buf).expect("read should have returned EOF (0)"));
        }
    }

    #[test]
    fn listener_timeout() {
        let listener = start_listener();
        let mut us = connect_to_listener(&listener);
        let mut buf = [0; 512];
        if cfg!(windows) {
            assert!(us.read(&mut buf).is_err());
        } else {
            assert_eq!(0,
                       us.read(&mut buf).expect("read should have returned EOF (0)"));
        }
    }

    #[test]
    fn stun_service() {
        let listener = start_listener();
        let mut us = connect_to_listener(&listener);

        let message = serialise(&Message::EchoAddrReq).unwrap();
        write(&mut us, message).expect("Could not write.");

        let our_addr = match read(&mut us).expect("Could not read.") {
            Message::EchoAddrResp(addr) => addr,
            msg => panic!("Unexpected message: {:?}", msg),
        };

        // This will not work if we are behind a NAT and are using a true STUN service. In that
        // case the following assertion should be commented out. Till then it is useful to have
        // this testing for conformity on local host.
        assert_eq!(our_addr.0,
                   us.local_addr().expect("Could not obtain local addr"));

        let mut buf = [0; 512];
        if cfg!(windows) {
            assert!(us.read(&mut buf).is_err());
        } else {
            assert_eq!(0,
                       us.read(&mut buf).expect("read should have returned EOF (0)"));
        }
    }
}
