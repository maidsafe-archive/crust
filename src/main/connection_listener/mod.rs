// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod check_reachability;
mod exchange_msg;

use self::exchange_msg::ExchangeMsg;
use common::{Core, NameHash, PeerInfo, State, Uid};
use main::{ConnectionMap, CrustConfig, Event};
use mio::net::TcpListener;
use mio::{Poll, PollOpt, Ready, Token};
use nat::ip_addr_is_global;
use nat::{MappedTcpSocket, MappingContext};
use net2::TcpBuilder;
use safe_crypto::{PublicEncryptKey, SecretEncryptKey};
use socket_collection::{DecryptContext, TcpSock};
use std::any::Any;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

const LISTENER_BACKLOG: i32 = 100;

/// Accepts connections and transitions each connection into `ExchangeMsg` state.
pub struct ConnectionListener<UID: Uid> {
    token: Token,
    cm: ConnectionMap<UID>,
    config: CrustConfig,
    event_tx: ::CrustEventSender<UID>,
    listener: TcpListener,
    name_hash: NameHash,
    our_uid: UID,
    timeout_sec: Option<u64>,
    accept_bootstrap: bool,
    our_pk: PublicEncryptKey,
    our_sk: SecretEncryptKey,
}

impl<UID: Uid> ConnectionListener<UID> {
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        handshake_timeout_sec: Option<u64>,
        port: u16,
        force_include_port: bool,
        our_uid: UID,
        name_hash: NameHash,
        cm: ConnectionMap<UID>,
        config: CrustConfig,
        mc: Arc<MappingContext>,
        our_listeners: Arc<Mutex<Vec<PeerInfo>>>,
        token: Token,
        event_tx: ::CrustEventSender<UID>,
        our_pk: PublicEncryptKey,
        our_sk: SecretEncryptKey,
    ) {
        let event_tx_0 = event_tx.clone();
        let finish =
            move |core: &mut Core, poll: &Poll, socket, mut mapped_addrs: Vec<SocketAddr>| {
                let checker = |s: &SocketAddr| ip_addr_is_global(&s.ip()) && s.port() == port;
                if force_include_port && port != 0 && !mapped_addrs.iter().any(checker) {
                    let global_addrs: Vec<_> = mapped_addrs
                        .iter()
                        .filter_map(|s| {
                            if ip_addr_is_global(&s.ip()) {
                                let mut s = *s;
                                s.set_port(port);
                                Some(s)
                            } else {
                                None
                            }
                        }).collect();
                    mapped_addrs.extend(global_addrs);
                }
                if let Err(e) = Self::handle_mapped_socket(
                    core,
                    poll,
                    handshake_timeout_sec,
                    socket,
                    mapped_addrs,
                    our_uid,
                    name_hash,
                    cm,
                    config,
                    our_listeners,
                    token,
                    event_tx.clone(),
                    our_pk,
                    our_sk,
                ) {
                    error!("TCP Listener failed to handle mapped socket: {:?}", e);
                    let _ = event_tx.send(Event::ListenerFailed);
                }
            };

        if let Err(e) = MappedTcpSocket::<_, UID>::start(core, poll, port, &mc, finish) {
            error!("Error starting tcp_listening_socket: {:?}", e);
            let _ = event_tx_0.send(Event::ListenerFailed);
        }
    }

    pub fn set_accept_bootstrap(&mut self, accept: bool) {
        self.accept_bootstrap = accept;
    }

    fn handle_mapped_socket(
        core: &mut Core,
        poll: &Poll,
        timeout_sec: Option<u64>,
        socket: TcpBuilder,
        mapped_addrs: Vec<SocketAddr>,
        our_uid: UID,
        name_hash: NameHash,
        cm: ConnectionMap<UID>,
        config: CrustConfig,
        our_listeners: Arc<Mutex<Vec<PeerInfo>>>,
        token: Token,
        event_tx: ::CrustEventSender<UID>,
        our_pk: PublicEncryptKey,
        our_sk: SecretEncryptKey,
    ) -> ::Res<()> {
        let listener = socket.listen(LISTENER_BACKLOG)?;
        let local_addr = listener.local_addr()?;

        let listener = TcpListener::from_std(listener)?;
        poll.register(&listener, token, Ready::readable(), PollOpt::edge())?;

        *unwrap!(our_listeners.lock()) = mapped_addrs
            .into_iter()
            .map(|addr| PeerInfo::new(addr, our_pk))
            .collect();

        let state = Self {
            token,
            cm,
            config,
            event_tx: event_tx.clone(),
            listener,
            name_hash,
            our_uid,
            timeout_sec,
            accept_bootstrap: false,
            our_pk,
            our_sk,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));
        let _ = event_tx.send(Event::ListenerStarted(local_addr.port()));

        Ok(())
    }

    fn accept(&self, core: &mut Core, poll: &Poll) {
        loop {
            match self.listener.accept() {
                Ok((socket, _)) => {
                    let mut socket = TcpSock::wrap(socket);
                    if let Err(e) = socket.set_decrypt_ctx(DecryptContext::anonymous_decrypt(
                        self.our_pk,
                        self.our_sk.clone(),
                    )) {
                        error!("Failed to set decryption context: {}", e);
                        continue;
                    }
                    if let Err(e) = ExchangeMsg::start(
                        core,
                        poll,
                        self.timeout_sec,
                        socket,
                        self.accept_bootstrap,
                        self.our_uid,
                        self.name_hash,
                        self.cm.clone(),
                        self.config.clone(),
                        self.event_tx.clone(),
                    ) {
                        debug!("Error accepting direct connection: {:?}", e);
                    }
                }
                Err(ref e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted =>
                {
                    return
                }
                Err(ref e) => {
                    debug!("Failed to accept new socket: {:?}", e);
                    return;
                }
            }
        }
    }
}

impl<UID: Uid> State for ConnectionListener<UID> {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_readable() {
            self.accept(core, poll);
        }
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let _ = poll.deregister(&self.listener);
        let _ = core.remove_state(self.token);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::exchange_msg::EXCHANGE_MSG_TIMEOUT_SEC;
    use super::*;
    use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
    use common::{
        self, CoreMessage, CrustUser, EventLoop, ExternalReachability, Message, NameHash, HASH_SIZE,
    };
    use maidsafe_utilities::event_sender::MaidSafeEventCategory;
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use main::Event;
    use mio::Token;
    use nat::MappingContext;
    use rand;
    use safe_crypto::gen_encrypt_keypair;
    use serde::de::DeserializeOwned;
    use serde::ser::Serialize;
    use std::collections::HashMap;
    use std::io::{Cursor, Read, Write};
    use std::mem;
    use std::net::SocketAddr as StdSocketAddr;
    use std::net::TcpStream;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tests::UniqueId;

    type ConnectionListener = super::ConnectionListener<UniqueId>;

    // Make sure this is < EXCHANGE_MSG_TIMEOUT_SEC else blocking reader socket in this test will
    // exit with an EAGAIN error (unless this is what is wanted).
    const HANDSHAKE_TIMEOUT_SEC: u64 = 5;
    const LISTENER_TOKEN: usize = 0;
    const NAME_HASH: NameHash = [1; HASH_SIZE];
    const NAME_HASH_2: NameHash = [2; HASH_SIZE];

    struct Listener {
        _el: EventLoop,
        uid: UniqueId,
        addr: SocketAddr,
        event_rx: mpsc::Receiver<Event<UniqueId>>,
    }

    fn start_listener(accept_bootstrap: bool) -> Listener {
        let el = unwrap!(common::spawn_event_loop(
            LISTENER_TOKEN + 1,
            Some("Connection Listener Test"),
        ));

        let (event_tx, event_rx) = mpsc::channel();
        let crust_sender =
            ::CrustEventSender::new(event_tx, MaidSafeEventCategory::Crust, mpsc::channel().0);

        let cm = Arc::new(Mutex::new(HashMap::new()));
        let mc = Arc::new(unwrap!(MappingContext::new(), "Could not get MC"));
        let config = Arc::new(Mutex::new(Default::default()));
        let listeners = Arc::new(Mutex::new(Vec::with_capacity(5)));
        let (our_pk, our_sk) = gen_encrypt_keypair();

        let listeners_clone = listeners.clone();
        let uid = rand::random();
        unwrap!(
            el.send(CoreMessage::new(move |core, poll| {
                ConnectionListener::start(
                    core,
                    poll,
                    Some(HANDSHAKE_TIMEOUT_SEC),
                    0,
                    false,
                    uid,
                    NAME_HASH,
                    cm,
                    config,
                    mc,
                    listeners_clone,
                    Token(LISTENER_TOKEN),
                    crust_sender,
                    our_pk,
                    our_sk,
                );
            })),
            "Could not send to tx"
        );

        for it in event_rx.iter() {
            match it {
                Event::ListenerStarted(_port) => break,
                _ => panic!("Unexpected event notification - {:?}", it),
            }
        }

        let (tx, rx) = mpsc::channel();
        unwrap!(
            el.send(CoreMessage::new(move |core, _| {
                let state = match core.get_state(Token(LISTENER_TOKEN)) {
                    Some(state) => state,
                    None => panic!("Listener not initialised"),
                };
                let mut state = state.borrow_mut();
                let listener = match state.as_any().downcast_mut::<ConnectionListener>() {
                    Some(l) => l,
                    None => panic!("Token reserved for ConnectionListener has something else."),
                };
                listener.set_accept_bootstrap(accept_bootstrap);
                unwrap!(tx.send(()));
            })),
            "Could not send to tx"
        );
        unwrap!(rx.recv());

        let listen_info = &unwrap!(listeners.lock())[0];
        Listener {
            _el: el,
            uid,
            addr: listen_info.addr,
            event_rx,
        }
    }

    fn connect_to_listener(listener: &Listener) -> TcpStream {
        let listener_addr = StdSocketAddr::new(listener.addr.ip(), listener.addr.port());
        let stream = unwrap!(
            TcpStream::connect(listener_addr),
            "Could not connect to listener"
        );
        unwrap!(
            stream.set_read_timeout(Some(Duration::from_secs(EXCHANGE_MSG_TIMEOUT_SEC + 1))),
            "Could not set read timeout."
        );

        stream
    }

    fn write(stream: &mut TcpStream, message: &[u8]) -> ::Res<()> {
        let mut size_vec = Vec::with_capacity(mem::size_of::<u32>());
        unwrap!(size_vec.write_u32::<LittleEndian>(message.len() as u32));

        stream.write_all(&size_vec)?;
        stream.write_all(message)?;

        Ok(())
    }

    #[allow(unsafe_code)]
    fn read<T: DeserializeOwned + Serialize>(stream: &mut TcpStream) -> ::Res<T> {
        let mut payload_size_buffer = [0; 4];
        stream.read_exact(&mut payload_size_buffer)?;

        let payload_size =
            Cursor::new(&payload_size_buffer[..]).read_u32::<LittleEndian>()? as usize;

        let mut payload = Vec::with_capacity(payload_size);
        unsafe {
            payload.set_len(payload_size);
        }
        stream.read_exact(&mut payload)?;

        Ok(unwrap!(deserialise(&payload), "Could not deserialise."))
    }

    fn bootstrap(
        name_hash: NameHash,
        ext_reachability: ExternalReachability,
        our_uid: UniqueId,
        listener: &Listener,
    ) {
        let mut us = connect_to_listener(listener);

        let expected_kind = match ext_reachability {
            ExternalReachability::NotRequired => CrustUser::Client,
            ExternalReachability::Required { .. } => CrustUser::Node,
        };

        let message = unwrap!(serialise(&Message::BootstrapRequest(
            our_uid,
            name_hash,
            ext_reachability,
        )));
        unwrap!(write(&mut us, &message), "Could not write.");

        match unwrap!(read::<Message<UniqueId>>(&mut us), "Could not read.") {
            Message::BootstrapGranted(peer_uid) => assert_eq!(peer_uid, listener.uid),
            msg => panic!("Unexpected message: {:?}", msg),
        }

        match unwrap!(listener.event_rx.recv(), "Could not read event channel") {
            Event::BootstrapAccept(peer_id, peer_kind) => {
                assert_eq!(peer_id, our_uid);
                assert_eq!(peer_kind, expected_kind);
            }
            event => panic!("Unexpected event notification: {:?}", event),
        }
    }

    fn connect(name_hash: NameHash, our_uid: UniqueId, listener: &Listener) {
        let mut us = connect_to_listener(listener);

        let message = unwrap!(serialise(&Message::Connect(our_uid, name_hash)));
        unwrap!(write(&mut us, &message), "Could not write.");

        let their_uid = match unwrap!(read(&mut us), "Could not read.") {
            Message::Connect(peer_uid, peer_hash) => {
                assert_eq!(peer_uid, listener.uid);
                assert_eq!(peer_hash, NAME_HASH);
                peer_uid
            }
            msg => panic!("Unexpected message: {:?}", msg),
        };

        if our_uid > their_uid {
            let message = unwrap!(serialise(&Message::ChooseConnection::<UniqueId>));
            unwrap!(write(&mut us, &message), "Could not write.");
        }

        match unwrap!(listener.event_rx.recv(), "Could not read event channel") {
            Event::ConnectSuccess(id) => assert_eq!(id, our_uid),
            event => panic!("Unexpected event notification: {:?}", event),
        }
    }

    #[test]
    fn bootstrap_with_correct_parameters() {
        let listener = start_listener(true);
        let uid = rand::random();
        bootstrap(NAME_HASH, ExternalReachability::NotRequired, uid, &listener);
    }

    #[test]
    #[should_panic]
    fn bootstrap_when_bootstrapping_is_disabled() {
        let listener = start_listener(false);
        let uid = rand::random();
        bootstrap(NAME_HASH, ExternalReachability::NotRequired, uid, &listener);
    }

    #[test]
    fn connect_with_correct_parameters() {
        let listener = start_listener(false);
        let uid = rand::random();
        connect(NAME_HASH, uid, &listener);
    }

    #[test]
    #[should_panic]
    fn connect_to_self() {
        let listener = start_listener(true);
        connect(NAME_HASH, listener.uid, &listener);
    }

    #[test]
    #[should_panic]
    fn bootstrap_with_invalid_version_hash() {
        let listener = start_listener(true);
        let uid = rand::random();
        bootstrap(
            NAME_HASH_2,
            ExternalReachability::NotRequired,
            uid,
            &listener,
        );
    }

    #[test]
    #[should_panic]
    fn connect_with_invalid_version_hash() {
        let listener = start_listener(true);
        let uid = rand::random();
        connect(NAME_HASH_2, uid, &listener);
    }

    #[test]
    #[should_panic]
    fn bootstrap_with_invalid_pub_key() {
        let listener = start_listener(true);
        bootstrap(
            NAME_HASH,
            ExternalReachability::NotRequired,
            listener.uid,
            &listener,
        );
    }

    #[test]
    #[should_panic]
    fn connect_with_invalid_pub_key() {
        let listener = start_listener(true);
        connect(NAME_HASH, listener.uid, &listener);
    }

    #[test]
    fn invalid_msg_exchange() {
        let listener = start_listener(true);
        let mut us = connect_to_listener(&listener);

        let message = unwrap!(serialise(&Message::Heartbeat::<UniqueId>));
        unwrap!(write(&mut us, &message), "Could not write.");

        let mut buf = [0; 512];
        assert_eq!(
            0,
            unwrap!(us.read(&mut buf), "read should have returned EOF (0)")
        );
    }

    #[test]
    fn listener_timeout() {
        let listener = start_listener(true);
        let mut us = connect_to_listener(&listener);
        let mut buf = [0; 512];
        assert_eq!(
            0,
            unwrap!(us.read(&mut buf), "read should have returned EOF (0)")
        );
    }

    #[test]
    fn stun_service() {
        let listener = start_listener(true);
        let mut us = connect_to_listener(&listener);

        let message = unwrap!(serialise(&Message::EchoAddrReq::<UniqueId>));
        unwrap!(write(&mut us, &message), "Could not write.");

        let our_addr = match unwrap!(read::<Message<UniqueId>>(&mut us), "Could not read.") {
            Message::EchoAddrResp(addr) => addr,
            msg => panic!("Unexpected message: {:?}", msg),
        };

        // This will not work if we are behind a NAT and are using a true STUN service. In that
        // case the following assertion should be commented out. Till then it is useful to have
        // this testing for conformity on local host.
        assert_eq!(
            our_addr,
            unwrap!(us.local_addr(), "Could not obtain local addr")
        );

        let mut buf = [0; 512];
        assert_eq!(
            0,
            unwrap!(us.read(&mut buf), "read should have returned EOF (0)")
        );
    }
}
