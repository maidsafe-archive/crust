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

#[macro_use]
pub mod utils;
pub use self::utils::{gen_config, get_event_sender, timebomb};

use std::collections::HashSet;
use std::net::SocketAddr as StdSocketAddr;
use std::str::FromStr;
use std::sync::atomic::{ATOMIC_USIZE_INIT, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use main::{Config, Event, Service};
use mio;
use common::socket_addr::SocketAddr;

fn localhost(port: u16) -> SocketAddr {
    use std::net::IpAddr;
    SocketAddr(StdSocketAddr::new(unwrap_result!(IpAddr::from_str("127.0.0.1")), port))
}

fn localhost_contact_info(port: u16) -> SocketAddr {
    localhost(port)
}

fn gen_service_discovery_port() -> u16 {
    const BASE: u16 = 40000;
    static COUNTER: AtomicUsize = ATOMIC_USIZE_INIT;

    BASE + COUNTER.fetch_add(1, Ordering::Relaxed) as u16
}

#[test]
fn bootstrap_two_services_and_exchange_messages() {
    let config0 = gen_config();
    let (event_tx0, event_rx0) = get_event_sender();
    let mut service0 = unwrap_result!(Service::with_config(event_tx0, config0));

    unwrap_result!(service0.start_listening_tcp());

    let port0 = expect_event!(event_rx0, Event::ListenerStarted(port) => port);

    let mut config1 = gen_config();
    config1.hard_coded_contacts = vec![localhost_contact_info(port0)];

    let (event_tx1, event_rx1) = get_event_sender();
    let mut service1 = unwrap_result!(Service::with_config(event_tx1, config1));

    unwrap_result!(service1.start_bootstrap(HashSet::new()));

    let peer_id0 = expect_event!(event_rx1, Event::BootstrapConnect(peer_id, _) => peer_id);
    assert_eq!(peer_id0, service0.id());

    let peer_id1 = expect_event!(event_rx0, Event::BootstrapAccept(peer_id) => peer_id);
    assert_eq!(peer_id1, service1.id());

    let message0 = b"hello from 0".to_vec();
    unwrap_result!(service0.send(peer_id1, message0.clone(), 0));

    expect_event!(event_rx1, Event::NewMessage(peer_id, data) => {
        assert_eq!(peer_id, peer_id0);
        assert_eq!(data, message0);
    });

    let message1 = b"hello from 1".to_vec();
    unwrap_result!(service1.send(peer_id0, message1.clone(), 0));

    expect_event!(event_rx0, Event::NewMessage(peer_id, data) => {
        assert_eq!(peer_id, peer_id1);
        assert_eq!(data, message1);
    });
}

#[test]
fn bootstrap_two_services_using_service_discovery() {
    let service_discovery_port = gen_service_discovery_port();

    let mut config = gen_config();
    config.service_discovery_port = Some(service_discovery_port);

    let (event_tx0, event_rx0) = get_event_sender();
    let mut service0 = unwrap_result!(Service::with_config(event_tx0, config.clone()));

    let (event_tx1, event_rx1) = get_event_sender();
    let mut service1 = unwrap_result!(Service::with_config(event_tx1, config));

    service0.start_service_discovery();
    service0.set_service_discovery_listen(true);
    unwrap_result!(service0.start_listening_tcp());

    expect_event!(event_rx0, Event::ListenerStarted(_port));

    service1.start_service_discovery();
    unwrap_result!(service1.start_bootstrap(HashSet::new()));

    let peer_id0 = expect_event!(event_rx1, Event::BootstrapConnect(peer_id, _) => peer_id);
    assert_eq!(peer_id0, service0.id());

    let peer_id1 = expect_event!(event_rx0, Event::BootstrapAccept(peer_id) => peer_id);
    assert_eq!(peer_id1, service1.id());
}

#[test]
fn bootstrap_with_multiple_contact_endpoints() {
    use std::net::TcpListener;

    let (event_tx0, event_rx0) = get_event_sender();
    let mut service0 = unwrap_result!(Service::with_config(event_tx0, Config::default()));
    unwrap_result!(service0.start_listening_tcp());
    let port = expect_event!(event_rx0, Event::ListenerStarted(port) => port);
    let valid_address = localhost(port);

    let deaf_listener = unwrap_result!(TcpListener::bind("127.0.0.1:0"));
    let invalid_address = SocketAddr(unwrap_result!(deaf_listener.local_addr()));

    let mut config1 = gen_config();
    config1.hard_coded_contacts = vec![invalid_address, valid_address];

    let (event_tx1, event_rx1) = get_event_sender();
    let mut service1 = unwrap_result!(Service::with_config(event_tx1, config1));
    unwrap_result!(service1.start_bootstrap(HashSet::new()));

    let peer_id0 = expect_event!(event_rx1, Event::BootstrapConnect(peer_id, _) => peer_id);
    assert_eq!(peer_id0, service0.id());

    let peer_id1 = expect_event!(event_rx0, Event::BootstrapAccept(peer_id) => peer_id);
    assert_eq!(peer_id1, service1.id());
}

#[test]
fn bootstrap_with_blacklist() {
    use std::net::TcpListener;

    let (event_tx0, event_rx0) = get_event_sender();
    let mut service0 = unwrap_result!(Service::with_config(event_tx0, Config::default()));
    unwrap_result!(service0.start_listening_tcp());
    let port = expect_event!(event_rx0, Event::ListenerStarted(port) => port);
    let valid_address = localhost(port);

    let blacklisted_listener = unwrap_result!(TcpListener::bind("127.0.0.1:0"));
    let blacklisted_address = SocketAddr(unwrap_result!(blacklisted_listener.local_addr()));

    let mut config1 = gen_config();
    config1.hard_coded_contacts = vec![blacklisted_address, valid_address];

    let (event_tx1, event_rx1) = get_event_sender();
    let mut service1 = unwrap_result!(Service::with_config(event_tx1, config1));
    let mut blacklist = HashSet::new();
    blacklist.insert(*blacklisted_address);
    unwrap_result!(service1.start_bootstrap(blacklist));

    let peer_id0 = expect_event!(event_rx1, Event::BootstrapConnect(peer_id, _) => peer_id);
    assert_eq!(peer_id0, service0.id());

    let peer_id1 = expect_event!(event_rx0, Event::BootstrapAccept(peer_id) => peer_id);
    assert_eq!(peer_id1, service1.id());

    let blacklisted_listener = unwrap_result!(
            mio::tcp::TcpListener::from_listener(blacklisted_listener, &*blacklisted_address)
    );
    thread::sleep(Duration::from_secs(5));
    let stream_opt = unwrap_result!(mio::TryAccept::accept(&blacklisted_listener));
    assert!(stream_opt.is_none())
}

#[test]
fn bootstrap_fails_if_there_are_no_contacts() {
    let config = gen_config();
    let (event_tx, event_rx) = get_event_sender();
    let mut service = unwrap_result!(Service::with_config(event_tx, config));

    unwrap_result!(service.start_bootstrap(HashSet::new()));
    expect_event!(event_rx, Event::BootstrapFailed);
}

#[test]
fn bootstrap_timeouts_if_there_are_only_invalid_contacts() {
    use std::net::TcpListener;

    let deaf_listener = unwrap_result!(TcpListener::bind("127.0.0.1:0"));
    let address = SocketAddr(unwrap_result!(deaf_listener.local_addr()));

    let mut config = gen_config();
    config.hard_coded_contacts = vec![address];

    let (event_tx, event_rx) = get_event_sender();
    let mut service = unwrap_result!(Service::with_config(event_tx, config));

    unwrap_result!(service.start_bootstrap(HashSet::new()));
    expect_event!(event_rx, Event::BootstrapFailed);
}

#[test]
fn drop_disconnects() {
    let config_0 = gen_config();
    let (event_tx_0, event_rx_0) = get_event_sender();
    let mut service_0 = unwrap_result!(Service::with_config(event_tx_0, config_0));

    unwrap_result!(service_0.start_listening_tcp());
    let port = expect_event!(event_rx_0, Event::ListenerStarted(port) => port);

    let mut config_1 = gen_config();
    config_1.hard_coded_contacts = vec![localhost_contact_info(port)];

    let (event_tx_1, event_rx_1) = get_event_sender();
    let mut service_1 = unwrap_result!(Service::with_config(event_tx_1, config_1));
    unwrap_result!(service_1.start_bootstrap(HashSet::new()));

    let peer_id_0 = expect_event!(event_rx_1, Event::BootstrapConnect(peer_id, _) => peer_id);
    expect_event!(event_rx_0, Event::BootstrapAccept(_peer_id));

    // Dropping service_0 should make service_1 receive a LostPeer event.
    drop(service_0);
    expect_event!(event_rx_1, Event::LostPeer(peer_id) => {
        assert_eq!(peer_id, peer_id_0)
    });
}

// This module implements a simulated crust peer which accepts incomming
// connections but then does nothing. It's purpose is to test that we detect
// and handle non-responsive peers correctly.
mod broken_peer {
    use std::any::Any;
    use std::cell::RefCell;
    use std::rc::Rc;

    use common::{Context, Core, Message, Socket, State};
    use mio::tcp::TcpListener;
    use mio::{EventLoop, EventSet, PollOpt, Token};
    use sodiumoxide::crypto::box_;

    pub struct Listen(TcpListener);

    impl Listen {
        pub fn start(core: &mut Core, event_loop: &mut EventLoop<Core>, listener: TcpListener) {
            let context = core.get_new_context();
            let token = core.get_new_token();
            let _ = core.insert_context(token, context);

            unwrap_result!(event_loop.register(&listener,
                                               token,
                                               EventSet::readable(),
                                               PollOpt::edge()));

            let state = Listen(listener);
            let _ = core.insert_state(context, Rc::new(RefCell::new(state)));
        }
    }

    impl State for Listen {
        fn ready(&mut self,
                 core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 token: Token,
                 _: EventSet) {
            match unwrap_result!(self.0.accept()) {
                Some((socket, _)) => {
                    unwrap_result!(event_loop.deregister(&self.0));

                    let socket = Socket::wrap(socket);
                    let context = core.get_context(token).unwrap();

                    Connection::start(core, event_loop, context, token, socket);
                }

                None => {
                    unwrap_result!(event_loop.register(&self.0,
                                                       token,
                                                       EventSet::readable(),
                                                       PollOpt::edge()));
                }
            }
        }

        fn as_any(&mut self) -> &mut Any {
            self
        }
    }

    struct Connection(Socket);

    impl Connection {
        fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 context: Context,
                 token: Token,
                 socket: Socket) {
            unwrap_result!(event_loop.register(&socket,
                                               token,
                                               EventSet::readable(),
                                               PollOpt::edge()));

            let state = Connection(socket);
            let _ = core.insert_state(context, Rc::new(RefCell::new(state)));
        }
    }

    impl State for Connection {
        fn ready(&mut self,
                 _: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 token: Token,
                 event_set: EventSet) {

            if event_set.is_readable() {
                match unwrap_result!(self.0.read::<Message>()) {
                    Some(Message::BootstrapRequest(..)) => {
                        let public_key = box_::gen_keypair().0;
                        unwrap_result!(self.0.write(event_loop,
                                                    token,
                                                    Some((Message::BootstrapResponse(public_key),
                                                          0))));
                    }
                    Some(_) | None => (),
                }
            }

            if event_set.is_writable() {
                unwrap_result!(self.0.write::<Message>(event_loop, token, None));
            }
        }

        fn as_any(&mut self) -> &mut Any {
            self
        }
    }
}

#[test]
#[ignore]
fn drop_peer_when_no_message_received_within_inactivity_period() {
    use std::thread;

    use common::{Core, CoreMessage};
    use maidsafe_utilities::thread::RaiiThreadJoiner;
    use mio::EventLoop;
    use mio::tcp::TcpListener;
    use self::broken_peer;
    use sodiumoxide;

    sodiumoxide::init();

    // Spin up the non-responsive peer.
    let mut event_loop = unwrap_result!(EventLoop::new());
    let mio_tx = event_loop.channel();

    let _joiner = RaiiThreadJoiner::new(thread::spawn(move || {
        let mut core = Core::new();
        unwrap_result!(event_loop.run(&mut core));
    }));

    let bind_addr = StdSocketAddr::from_str("127.0.0.1:0").expect("Could not parse addr");
    let listener = TcpListener::bind(&bind_addr).expect("Could not bind listener");
    let address = SocketAddr(unwrap_result!(listener.local_addr()));

    unwrap_result!(mio_tx.send(CoreMessage::new(|core, event_loop| {
        broken_peer::Listen::start(core, event_loop, listener)
    })));

    // Spin up normal service that will connect to the above guy.
    let mut config = gen_config();
    config.hard_coded_contacts = vec![address];

    let (event_tx, event_rx) = get_event_sender();
    let mut service = unwrap_result!(Service::with_config(event_tx, config));

    unwrap_result!(service.start_bootstrap(HashSet::new()));
    let peer_id = expect_event!(event_rx, Event::BootstrapConnect(peer_id, _) => peer_id);

    // The peer should drop after inactivity.
    expect_event!(event_rx, Event::LostPeer(lost_peer_id) => {
        assert_eq!(lost_peer_id, peer_id)
    });

    unwrap_result!(mio_tx.send(CoreMessage::new(|_, event_loop| event_loop.shutdown())));
}

#[test]
fn do_not_drop_peer_even_when_no_data_messages_are_exchanged_within_inactivity_period() {
    use std::thread;
    use std::time::Duration;
    use main::INACTIVITY_TIMEOUT_MS;

    let config0 = gen_config();
    let (event_tx0, event_rx0) = get_event_sender();
    let mut service0 = unwrap_result!(Service::with_config(event_tx0, config0));

    unwrap_result!(service0.start_listening_tcp());
    let port0 = expect_event!(event_rx0, Event::ListenerStarted(port) => port);

    let mut config1 = gen_config();
    config1.hard_coded_contacts = vec![localhost_contact_info(port0)];

    let (event_tx1, event_rx1) = get_event_sender();
    let mut service1 = unwrap_result!(Service::with_config(event_tx1, config1));

    unwrap_result!(service1.start_bootstrap(HashSet::new()));
    expect_event!(event_rx1, Event::BootstrapConnect(_peer_id, _));
    expect_event!(event_rx0, Event::BootstrapAccept(_peer_id));

    thread::sleep(Duration::from_millis(2 * INACTIVITY_TIMEOUT_MS));

    match event_rx0.try_recv() {
        Ok(Event::LostPeer(..)) => panic!("peer lost unexpectedly"),
        _ => (),
    }

    match event_rx1.try_recv() {
        Ok(Event::LostPeer(..)) => panic!("peer lost unexpectedly"),
        _ => (),
    }
}
