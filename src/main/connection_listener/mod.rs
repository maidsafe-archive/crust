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

use common::{Core, NameHash, Socket, State};
use main::{ConnectionMap, Event};
use mio::{EventLoop, EventSet, PollOpt, Token};
use mio::tcp::TcpListener;
use nat::{MappedTcpSocket, MappingContext};
use net2::TcpBuilder;
use rust_sodium::crypto::box_::PublicKey;
use self::exchange_msg::ExchangeMsg;
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

const LISTENER_BACKLOG: i32 = 100;

pub struct ConnectionListener {
    token: Token,
    cm: ConnectionMap,
    event_tx: ::CrustEventSender,
    listener: TcpListener,
    name_hash: NameHash,
    our_pk: PublicKey,
    timeout_ms: Option<u64>,
}

impl ConnectionListener {
    pub fn start(core: &mut Core,
                 el: &mut EventLoop<Core>,
                 handshake_timeout_ms: Option<u64>,
                 port: u16,
                 our_pk: PublicKey,
                 name_hash: NameHash,
                 cm: ConnectionMap,
                 mc: Arc<MappingContext>,
                 our_listeners: Arc<Mutex<Vec<SocketAddr>>>,
                 token: Token,
                 event_tx: ::CrustEventSender) {
        let event_tx_0 = event_tx.clone();
        let finish = move |core: &mut Core, el: &mut EventLoop<Core>, socket, mapped_addrs| {
            if let Err(e) = ConnectionListener::handle_mapped_socket(core,
                                                                     el,
                                                                     handshake_timeout_ms,
                                                                     socket,
                                                                     mapped_addrs,
                                                                     our_pk,
                                                                     name_hash,
                                                                     cm,
                                                                     our_listeners,
                                                                     token,
                                                                     event_tx.clone()) {
                error!("TCP Listener failed to handle mapped socket: {:?}", e);
                let _ = event_tx.send(Event::ListenerFailed);
            }
        };

        if let Err(e) = MappedTcpSocket::start(core, el, port, &mc, finish) {
            error!("Error starting tcp_listening_socket: {:?}", e);
            let _ = event_tx_0.send(Event::ListenerFailed);
        }
    }

    fn handle_mapped_socket(core: &mut Core,
                            el: &mut EventLoop<Core>,
                            timeout_ms: Option<u64>,
                            socket: TcpBuilder,
                            mapped_addrs: Vec<SocketAddr>,
                            our_pk: PublicKey,
                            name_hash: NameHash,
                            cm: ConnectionMap,
                            our_listeners: Arc<Mutex<Vec<SocketAddr>>>,
                            token: Token,
                            event_tx: ::CrustEventSender)
                            -> ::Res<()> {
        let listener = socket.listen(LISTENER_BACKLOG)?;
        let local_addr = listener.local_addr()?;

        let listener = TcpListener::from_listener(listener, &local_addr)?;
        el.register(&listener,
                      token,
                      EventSet::readable() | EventSet::error() | EventSet::hup(),
                      PollOpt::edge())?;

        *unwrap!(our_listeners.lock()) = mapped_addrs.into_iter().collect();

        let state = ConnectionListener {
            token: token,
            cm: cm,
            event_tx: event_tx.clone(),
            listener: listener,
            name_hash: name_hash,
            our_pk: our_pk,
            timeout_ms: timeout_ms,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));
        let _ = event_tx.send(Event::ListenerStarted(local_addr.port()));

        Ok(())
    }

    fn accept(&self, core: &mut Core, el: &mut EventLoop<Core>) {
        loop {
            match self.listener.accept() {
                Ok(Some((socket, _))) => {
                    if let Err(e) = ExchangeMsg::start(core,
                                                       el,
                                                       self.timeout_ms,
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
    fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, es: EventSet) {
        if es.is_error() || es.is_hup() {
            self.terminate(core, el);
            let _ = self.event_tx.send(Event::ListenerFailed);
        } else if es.is_readable() {
            self.accept(core, el);
        }
    }

    fn terminate(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        let _ = el.deregister(&self.listener);
        let _ = core.remove_state(self.token);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

#[cfg(test)]
mod test {

    use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
    use common::{self, Core, CoreMessage, Message, NameHash};
    use maidsafe_utilities;
    use maidsafe_utilities::event_sender::MaidSafeEventCategory;
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use maidsafe_utilities::thread::Joiner;
    use main::{Event, PeerId};
    use mio::{EventLoop, Sender, Token};
    use nat::MappingContext;
    use rust_sodium::crypto::box_::{self, PublicKey};
    use rust_sodium::crypto::hash::sha256;
    use rustc_serialize::Decodable;

    use std::collections::HashMap;
    use std::io::{Cursor, Read, Write};
    use std::mem;
    use std::net::SocketAddr as StdSocketAddr;
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};
    use std::sync::mpsc;
    use std::time::Duration;
    use super::*;
    use super::exchange_msg::EXCHANGE_MSG_TIMEOUT_MS;

    const NAME_HASH: NameHash = [1; sha256::DIGESTBYTES];
    const NAME_HASH_2: NameHash = [2; sha256::DIGESTBYTES];

    struct Listener {
        tx: Sender<CoreMessage>,
        pk: PublicKey,
        addr: common::SocketAddr,
        event_rx: mpsc::Receiver<Event>,
        _raii_joiner: Joiner,
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            unwrap!(self.tx
                        .send(CoreMessage::new(|_, el| el.shutdown())),
                    "Could not send shutdown to el");
        }
    }

    fn start_listener() -> Listener {
        let mut el = unwrap!(EventLoop::new(), "Could not spawn el");
        let tx = el.channel();
        let raii_joiner = maidsafe_utilities::thread::named("EL", move || {
            unwrap!(el.run(&mut Core::with_token_counter(1)), "Could not run el");
        });

        let (event_tx, event_rx) = mpsc::channel();
        let crust_sender =
            ::CrustEventSender::new(event_tx, MaidSafeEventCategory::Crust, mpsc::channel().0);

        let cm = Arc::new(Mutex::new(HashMap::new()));
        let mc = Arc::new(unwrap!(MappingContext::new(), "Could not get MC"));
        let listeners = Arc::new(Mutex::new(Vec::with_capacity(5)));

        let listeners_clone = listeners.clone();
        let (pk, _) = box_::gen_keypair();
        unwrap!(tx.send(CoreMessage::new(move |core, el| {
            ConnectionListener::start(core,
                                      el,
                                      Some(5000),
                                      0,
                                      pk,
                                      NAME_HASH,
                                      cm,
                                      mc,
                                      listeners_clone,
                                      Token(0),
                                      crust_sender);
        })),
                "Could not send to tx");

        for it in event_rx.iter() {
            match it {
                Event::ListenerStarted(_port) => break,
                _ => panic!("Unexpected event notification - {:?}", it),
            }
        }

        let addr = common::SocketAddr(unwrap!(listeners.lock())[0]);

        Listener {
            tx: tx,
            pk: pk,
            addr: addr,
            event_rx: event_rx,
            _raii_joiner: raii_joiner,
        }
    }

    fn connect_to_listener(listener: &Listener) -> TcpStream {
        let listener_addr = StdSocketAddr::new(listener.addr.ip(), listener.addr.port());
        let stream = unwrap!(TcpStream::connect(listener_addr),
                             "Could not connect to listener");
        unwrap!(stream.set_read_timeout(Some(Duration::from_millis(EXCHANGE_MSG_TIMEOUT_MS + 1000)))
            , "Could not set read timeout.");

        stream
    }

    fn write(stream: &mut TcpStream, message: Vec<u8>) -> ::Res<()> {
        let mut size_vec = Vec::with_capacity(mem::size_of::<u32>());
        unwrap!(size_vec.write_u32::<LittleEndian>(message.len() as u32));

        stream.write_all(&size_vec)?;
        stream.write_all(&message)?;

        Ok(())
    }

    #[allow(unsafe_code)]
    fn read<T: Decodable>(stream: &mut TcpStream) -> ::Res<T> {
        let mut payload_size_buffer = [0; 4];
        stream.read_exact(&mut payload_size_buffer)?;

        let payload_size = Cursor::new(&payload_size_buffer[..]).read_u32::<LittleEndian>()? as
                           usize;

        let mut payload = Vec::with_capacity(payload_size);
        unsafe {
            payload.set_len(payload_size);
        }
        stream.read_exact(&mut payload)?;

        Ok(unwrap!(deserialise(&payload), "Could not deserialise."))
    }

    fn bootstrap(name_hash: NameHash, pk: PublicKey, listener: Listener) {
        let mut us = connect_to_listener(&listener);

        let message = unwrap!(serialise(&Message::BootstrapRequest(pk, name_hash)));
        unwrap!(write(&mut us, message), "Could not write.");

        match unwrap!(read(&mut us), "Could not read.") {
            Message::BootstrapResponse(peer_pk) => assert_eq!(peer_pk, listener.pk),
            msg => panic!("Unexpected message: {:?}", msg),
        }

        match unwrap!(listener.event_rx.recv(), "Could not read event channel") {
            Event::BootstrapAccept(peer_id) => assert_eq!(peer_id, PeerId(pk)),
            event => panic!("Unexpected event notification: {:?}", event),
        }
    }

    fn connect(name_hash: NameHash, pk: PublicKey, listener: Listener) {
        let mut us = connect_to_listener(&listener);

        let message = unwrap!(serialise(&Message::Connect(pk, name_hash)));
        unwrap!(write(&mut us, message), "Could not write.");

        let our_id = PeerId(pk);
        let their_id = match unwrap!(read(&mut us), "Could not read.") {
            Message::Connect(peer_pk, peer_hash) => {
                assert_eq!(peer_pk, listener.pk);
                assert_eq!(peer_hash, NAME_HASH);
                PeerId(peer_pk)
            }
            msg => panic!("Unexpected message: {:?}", msg),
        };

        if our_id > their_id {
            let message = unwrap!(serialise(&Message::ChooseConnection));
            unwrap!(write(&mut us, message), "Could not write.");
        }

        match unwrap!(listener.event_rx.recv(), "Could not read event channel") {
            Event::ConnectSuccess(id) => assert_eq!(id, PeerId(pk)),
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
        bootstrap(NAME_HASH_2, pk, listener);
    }

    #[test]
    #[should_panic]
    fn connect_with_invalid_version_hash() {
        let listener = start_listener();
        let (pk, _) = box_::gen_keypair();
        connect(NAME_HASH_2, pk, listener);
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

        let message = unwrap!(serialise(&Message::Heartbeat));
        unwrap!(write(&mut us, message), "Could not write.");

        let mut buf = [0; 512];
        if cfg!(windows) {
            assert!(us.read(&mut buf).is_err());
        } else {
            assert_eq!(0,
                       unwrap!(us.read(&mut buf), "read should have returned EOF (0)"));
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
                       unwrap!(us.read(&mut buf), "read should have returned EOF (0)"));
        }
    }

    // TODO(Spandan) Due to mio bug this will fail on windows.
    //               Track https://github.com/carllerche/mio/issues/397
    #[cfg(target_family = "unix")]
    #[test]
    fn stun_service() {
        let listener = start_listener();
        let mut us = connect_to_listener(&listener);

        let message = unwrap!(serialise(&Message::EchoAddrReq));
        unwrap!(write(&mut us, message), "Could not write.");

        let our_addr = match unwrap!(read(&mut us), "Could not read.") {
            Message::EchoAddrResp(addr) => addr,
            msg => panic!("Unexpected message: {:?}", msg),
        };

        // This will not work if we are behind a NAT and are using a true STUN service. In that
        // case the following assertion should be commented out. Till then it is useful to have
        // this testing for conformity on local host.
        assert_eq!(our_addr.0,
                   unwrap!(us.local_addr(), "Could not obtain local addr"));

        let mut buf = [0; 512];
        if cfg!(windows) {
            assert!(us.read(&mut buf).is_err());
        } else {
            assert_eq!(0,
                       unwrap!(us.read(&mut buf), "read should have returned EOF (0)"));
        }
    }
}
