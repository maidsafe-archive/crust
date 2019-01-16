// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod exchange_msg;

use self::exchange_msg::ExchangeMsg;
use crate::common::{NameHash, PeerInfo, State, Uid};
use crate::main::{CrustData, Event, EventLoopCore};
use crate::nat::ip_addr_is_global;
use crate::nat::{MappedTcpSocket, MappingContext};
use mio::net::TcpListener;
use mio::{Poll, PollOpt, Ready, Token};
use net2::TcpBuilder;
use safe_crypto::{PublicEncryptKey, SecretEncryptKey};
use socket_collection::{DecryptContext, TcpSock};
use std::any::Any;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;

const LISTENER_BACKLOG: i32 = 100;

/// Accepts connections and transitions each connection into `ExchangeMsg` state.
/// Optionally will make `ExchangeMsg` to test for peer external reachability. This behavior
/// is enabled by default.
pub struct ConnectionListener<UID: Uid> {
    token: Token,
    event_tx: crate::CrustEventSender<UID>,
    listener: TcpListener,
    name_hash: NameHash,
    our_uid: UID,
    timeout_sec: Option<u64>,
    accept_bootstrap: bool,
    our_pk: PublicEncryptKey,
    our_sk: SecretEncryptKey,
    test_ext_reachability: bool,
}

impl<UID: Uid> ConnectionListener<UID> {
    pub fn start(
        core: &mut EventLoopCore<UID>,
        poll: &Poll,
        handshake_timeout_sec: Option<u64>,
        port: u16,
        force_include_port: bool,
        our_uid: UID,
        name_hash: NameHash,
        mc: Arc<MappingContext>,
        token: Token,
        event_tx: crate::CrustEventSender<UID>,
        our_pk: PublicEncryptKey,
        our_sk: SecretEncryptKey,
    ) {
        let event_tx_0 = event_tx.clone();
        let our_sk2 = our_sk.clone();

        let finish = move |core: &mut EventLoopCore<UID>,
                           poll: &Poll,
                           socket,
                           mut mapped_addrs: Vec<SocketAddr>| {
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
                    })
                    .collect();
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
                token,
                event_tx.clone(),
                our_pk,
                our_sk,
            ) {
                error!("TCP Listener failed to handle mapped socket: {:?}", e);
                let _ = event_tx.send(Event::ListenerFailed);
            }
        };

        if let Err(e) =
            MappedTcpSocket::<_, UID, _>::start(core, poll, port, &mc, our_pk, &our_sk2, finish)
        {
            error!("Error starting tcp_listening_socket: {:?}", e);
            let _ = event_tx_0.send(Event::ListenerFailed);
        }
    }

    pub fn set_accept_bootstrap(&mut self, accept: bool) {
        self.accept_bootstrap = accept;
    }

    /// Enables/disables peer external reachability test.
    pub fn set_ext_reachability_test(&mut self, test: bool) {
        self.test_ext_reachability = test;
    }

    fn handle_mapped_socket(
        core: &mut EventLoopCore<UID>,
        poll: &Poll,
        timeout_sec: Option<u64>,
        socket: TcpBuilder,
        mapped_addrs: Vec<SocketAddr>,
        our_uid: UID,
        name_hash: NameHash,
        token: Token,
        event_tx: crate::CrustEventSender<UID>,
        our_pk: PublicEncryptKey,
        our_sk: SecretEncryptKey,
    ) -> crate::Res<()> {
        let listener = socket.listen(LISTENER_BACKLOG)?;
        let local_addr = listener.local_addr()?;

        let listener = TcpListener::from_std(listener)?;
        poll.register(&listener, token, Ready::readable(), PollOpt::edge())?;

        core.user_data_mut().our_listeners.extend(
            mapped_addrs
                .into_iter()
                .map(|addr| PeerInfo::new(addr, our_pk)),
        );

        let state = Self {
            token,
            event_tx: event_tx.clone(),
            listener,
            name_hash,
            our_uid,
            timeout_sec,
            accept_bootstrap: false,
            our_pk,
            our_sk,
            test_ext_reachability: true,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));
        let _ = event_tx.send(Event::ListenerStarted(local_addr.port()));

        Ok(())
    }

    fn accept(&self, core: &mut EventLoopCore<UID>, poll: &Poll) {
        loop {
            match self.listener.accept() {
                Ok((socket, _)) => {
                    let mut socket = TcpSock::wrap(socket);
                    if let Err(e) = socket.set_decrypt_ctx(DecryptContext::anonymous_decrypt(
                        self.our_pk,
                        self.our_sk.clone(),
                    )) {
                        warn!("Failed to set decryption context: {}", e);
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
                        self.event_tx.clone(),
                        self.our_pk,
                        &self.our_sk,
                        self.test_ext_reachability,
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

impl<UID: Uid> State<CrustData<UID>> for ConnectionListener<UID> {
    fn ready(&mut self, core: &mut EventLoopCore<UID>, poll: &Poll, kind: Ready) {
        if kind.is_readable() {
            self.accept(core, poll);
        }
    }

    fn terminate(&mut self, core: &mut EventLoopCore<UID>, poll: &Poll) {
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
    use crate::common::{
        self, BootstrapperRole, CoreMessage, CrustUser, Message, NameHash, HASH_SIZE,
    };
    use crate::main::bootstrap::Cache as BootstrapCache;
    use crate::main::{Event, EventLoop};
    use crate::nat::MappingContext;
    use crate::tests::UniqueId;
    use maidsafe_utilities::event_sender::MaidSafeEventCategory;
    use mio::Events;
    use mio::Token;
    use rand;
    use safe_crypto::gen_encrypt_keypair;
    use socket_collection::{EncryptContext, SocketError};
    use std::io::Read;
    use std::net::SocketAddr as StdSocketAddr;
    use std::net::TcpStream;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    type ConnectionListener = super::ConnectionListener<UniqueId>;

    // Make sure this is < EXCHANGE_MSG_TIMEOUT_SEC else blocking reader socket in this test will
    // exit with an EAGAIN error (unless this is what is wanted).
    const HANDSHAKE_TIMEOUT_SEC: u64 = 5;
    const LISTENER_TOKEN: usize = 0;
    const NAME_HASH: NameHash = [1; HASH_SIZE];
    const NAME_HASH_2: NameHash = [2; HASH_SIZE];

    struct Listener {
        _el: EventLoop<UniqueId>,
        uid: UniqueId,
        addr: SocketAddr,
        event_rx: mpsc::Receiver<Event<UniqueId>>,
        pub_key: PublicEncryptKey,
    }

    fn start_listener(accept_bootstrap: bool) -> Listener {
        let el = unwrap!(common::spawn_event_loop(
            LISTENER_TOKEN + 1,
            Some("Connection Listener Test"),
            || CrustData::new(BootstrapCache::new(None)),
        ));

        let (event_tx, event_rx) = mpsc::channel();
        let crust_sender =
            crate::CrustEventSender::new(event_tx, MaidSafeEventCategory::Crust, mpsc::channel().0);

        let mc = Arc::new(unwrap!(MappingContext::try_new(), "Could not get MC"));
        let (our_pk, our_sk) = gen_encrypt_keypair();

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
                    mc,
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
            el.send(CoreMessage::new(
                move |core: &mut EventLoopCore<UniqueId>, _| {
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
                    listener.set_ext_reachability_test(false);

                    let listener_info =
                        unwrap!(core.user_data_mut().our_listeners.iter().nth(0).cloned());
                    unwrap!(tx.send(listener_info));
                }
            )),
            "Could not send to tx"
        );
        let listener_info = unwrap!(rx.recv());

        Listener {
            _el: el,
            uid,
            addr: listener_info.addr,
            event_rx,
            pub_key: our_pk,
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

    fn bootstrap(name_hash: NameHash, our_uid: UniqueId, listener: &Listener) {
        const SOCKET_TOKEN: Token = Token(0);
        let el = unwrap!(Poll::new());

        let (our_pk, our_sk) = gen_encrypt_keypair();
        let mut sock = unwrap!(TcpSock::connect(&listener.addr));
        unwrap!(sock.set_encrypt_ctx(EncryptContext::anonymous_encrypt(listener.pub_key)));
        let shared_key = our_sk.shared_secret(&listener.pub_key);
        unwrap!(sock.set_decrypt_ctx(DecryptContext::authenticated(shared_key)));
        unwrap!(el.register(&sock, SOCKET_TOKEN, Ready::writable(), PollOpt::edge(),));

        let message =
            Message::BootstrapRequest(our_uid, name_hash, BootstrapperRole::Client, our_pk);

        let mut events = Events::with_capacity(16);
        let msg = 'event_loop: loop {
            let _ = unwrap!(el.poll(&mut events, None));
            for ev in events.iter() {
                match ev.token() {
                    SOCKET_TOKEN => {
                        if ev.readiness().is_writable() {
                            let sent = unwrap!(sock.write(Some((message.clone(), 0))));
                            assert!(sent);
                            unwrap!(el.reregister(
                                &sock,
                                SOCKET_TOKEN,
                                Ready::readable(),
                                PollOpt::edge(),
                            ));
                        }
                        if ev.readiness().is_readable() {
                            let msg: Message<UniqueId> = unwrap!(unwrap!(sock.read()));
                            break 'event_loop msg;
                        }
                    }
                    _ => panic!("Unexpected event"),
                }
            }
        };

        match msg {
            Message::BootstrapGranted(peer_uid) => assert_eq!(peer_uid, listener.uid),
            msg => panic!("Unexpected message: {:?}", msg),
        }

        match unwrap!(listener.event_rx.recv(), "Could not read event channel") {
            Event::BootstrapAccept(peer_id, peer_kind) => {
                assert_eq!(peer_id, our_uid);
                assert_eq!(peer_kind, CrustUser::Client);
            }
            event => panic!("Unexpected event notification: {:?}", event),
        }
    }

    fn connect(name_hash: NameHash, our_uid: UniqueId, listener: &Listener) {
        const SOCKET_TOKEN: Token = Token(0);
        let el = unwrap!(Poll::new());

        let (our_pk, our_sk) = gen_encrypt_keypair();
        let mut sock = unwrap!(TcpSock::connect(&listener.addr));
        unwrap!(sock.set_encrypt_ctx(EncryptContext::anonymous_encrypt(listener.pub_key)));
        let shared_key = our_sk.shared_secret(&listener.pub_key);
        unwrap!(sock.set_decrypt_ctx(DecryptContext::authenticated(shared_key.clone())));
        unwrap!(el.register(&sock, SOCKET_TOKEN, Ready::writable(), PollOpt::edge()));

        let message = Message::ConnectRequest(our_uid, name_hash, Default::default(), our_pk);

        let mut events = Events::with_capacity(16);
        'event_loop: loop {
            let _ = unwrap!(el.poll(&mut events, None));
            for ev in events.iter() {
                match ev.token() {
                    SOCKET_TOKEN => {
                        if ev.readiness().is_writable() {
                            let sent = unwrap!(sock.write(Some((message.clone(), 0))));
                            assert!(sent);
                            unwrap!(el.reregister(
                                &sock,
                                SOCKET_TOKEN,
                                Ready::readable(),
                                PollOpt::edge(),
                            ));
                        }
                        if ev.readiness().is_readable() {
                            let msg: Message<UniqueId> = unwrap!(unwrap!(sock.read()));
                            let their_uid = match msg {
                                Message::ConnectResponse(peer_uid, peer_hash) => {
                                    assert_eq!(peer_uid, listener.uid);
                                    assert_eq!(peer_hash, NAME_HASH);

                                    unwrap!(sock.set_encrypt_ctx(EncryptContext::authenticated(
                                        shared_key
                                    )));
                                    peer_uid
                                }
                                msg => panic!("Unexpected message: {:?}", msg),
                            };
                            if our_uid > their_uid {
                                let message = Message::ChooseConnection::<UniqueId>;
                                let sent = unwrap!(sock.write(Some((message, 0))));
                                assert!(sent);
                            }
                            break 'event_loop;
                        }
                    }
                    _ => panic!("Unexpected event"),
                }
            }
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
        bootstrap(NAME_HASH, uid, &listener);
    }

    #[test]
    #[should_panic]
    fn bootstrap_when_bootstrapping_is_disabled() {
        let listener = start_listener(false);
        let uid = rand::random();
        bootstrap(NAME_HASH, uid, &listener);
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
        bootstrap(NAME_HASH_2, uid, &listener);
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
        bootstrap(NAME_HASH, listener.uid, &listener);
    }

    #[test]
    #[should_panic]
    fn connect_with_invalid_pub_key() {
        let listener = start_listener(true);
        connect(NAME_HASH, listener.uid, &listener);
    }

    #[test]
    fn invalid_msg_terminates_connection() {
        let listener = start_listener(true);
        const SOCKET_TOKEN: Token = Token(0);
        let el = unwrap!(Poll::new());

        let mut sock = unwrap!(TcpSock::connect(&listener.addr));
        let enc_ctx = EncryptContext::anonymous_encrypt(listener.pub_key);
        unwrap!(sock.set_encrypt_ctx(enc_ctx));
        unwrap!(el.register(&sock, SOCKET_TOKEN, Ready::writable(), PollOpt::edge(),));
        let message = Message::Heartbeat::<UniqueId>;

        let mut events = Events::with_capacity(16);
        let read_res = 'event_loop: loop {
            let _ = unwrap!(el.poll(&mut events, None));
            for ev in events.iter() {
                match ev.token() {
                    SOCKET_TOKEN => {
                        if ev.readiness().is_writable() {
                            let sent = unwrap!(sock.write(Some((message.clone(), 0))));
                            assert!(sent);
                            unwrap!(el.reregister(
                                &sock,
                                SOCKET_TOKEN,
                                Ready::readable(),
                                PollOpt::edge(),
                            ));
                        }
                        if ev.readiness().is_readable() {
                            let res = sock.read::<Message<UniqueId>>();
                            break 'event_loop res;
                        }
                    }
                    _ => panic!("Unexpected event"),
                }
            }
        };

        match read_res {
            Err(SocketError::ZeroByteRead) => (),
            r => panic!("Unexpected result: {:?}", r),
        }
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
        // TODO(povilas): use GetExtAddr for this test.
        let listener = start_listener(true);
        const SOCKET_TOKEN: Token = Token(0);
        let el = unwrap!(Poll::new());

        let mut sock = unwrap!(TcpSock::connect(&listener.addr));
        let enc_ctx = EncryptContext::anonymous_encrypt(listener.pub_key);
        unwrap!(sock.set_encrypt_ctx(enc_ctx));
        unwrap!(el.register(&sock, SOCKET_TOKEN, Ready::writable(), PollOpt::edge(),));

        let (our_pk, our_sk) = gen_encrypt_keypair();
        let message = Message::EchoAddrReq::<UniqueId>(our_pk);

        let shared_key = our_sk.shared_secret(&listener.pub_key);
        let dec_ctx = DecryptContext::authenticated(shared_key);
        unwrap!(sock.set_decrypt_ctx(dec_ctx));

        let mut events = Events::with_capacity(16);
        let msg = 'event_loop: loop {
            let _ = unwrap!(el.poll(&mut events, None));
            for ev in events.iter() {
                match ev.token() {
                    SOCKET_TOKEN => {
                        if ev.readiness().is_writable() {
                            let sent = unwrap!(sock.write(Some((message.clone(), 0))));
                            assert!(sent);
                            unwrap!(el.reregister(
                                &sock,
                                SOCKET_TOKEN,
                                Ready::readable(),
                                PollOpt::edge(),
                            ));
                        }
                        if ev.readiness().is_readable() {
                            let msg: Message<UniqueId> = unwrap!(unwrap!(sock.read()));
                            break 'event_loop msg;
                        }
                    }
                    _ => panic!("Unexpected event"),
                }
            }
        };

        let our_addr = match msg {
            Message::EchoAddrResp(addr) => addr,
            msg => panic!("Unexpected message: {:?}", msg),
        };

        // This will not work if we are behind a NAT and are using a true STUN service. In that
        // case the following assertion should be commented out. Till then it is useful to have
        // this testing for conformity on local host.
        assert_eq!(
            our_addr,
            unwrap!(sock.local_addr(), "Could not obtain local addr")
        );
        match sock.read::<Option<Message<UniqueId>>>() {
            Err(SocketError::ZeroByteRead) => (),
            r => panic!("Unexpected result: {:?}", r),
        }
    }
}
