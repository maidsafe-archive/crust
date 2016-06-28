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

use common::SocketAddr;
use main::{Config, Event, Service};
use mio;

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
fn bootstrap_fails_only_blacklisted_contact() {
    use std::net::TcpListener;

    let blacklisted_listener = unwrap_result!(TcpListener::bind("127.0.0.1:0"));
    let blacklisted_address = SocketAddr(unwrap_result!(blacklisted_listener.local_addr()));

    let mut config = gen_config();
    config.hard_coded_contacts = vec![blacklisted_address];
    let (event_tx, event_rx) = get_event_sender();
    let mut service = unwrap_result!(Service::with_config(event_tx, config));

    let mut blacklist = HashSet::new();
    blacklist.insert(*blacklisted_address);
    unwrap_result!(service.start_bootstrap(blacklist));

    expect_event!(event_rx, Event::BootstrapFailed);

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

    use common::{Core, Message, Socket, State};
    use mio::tcp::TcpListener;
    use mio::{EventLoop, EventSet, PollOpt, Token};
    use sodiumoxide::crypto::box_;

    pub struct Listen(TcpListener, Token);

    impl Listen {
        pub fn start(core: &mut Core, el: &mut EventLoop<Core>, listener: TcpListener) {
            let token = core.get_new_token();

            unwrap_result!(el.register(&listener, token, EventSet::readable(), PollOpt::edge()));

            let state = Listen(listener, token);
            let _ = core.insert_state(token, Rc::new(RefCell::new(state)));
        }
    }

    impl State for Listen {
        fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, _: EventSet) {
            match unwrap_result!(self.0.accept()) {
                Some((socket, _)) => {
                    unwrap_result!(el.deregister(&self.0));

                    let socket = Socket::wrap(socket);
                    Connection::start(core, el, self.1, socket);
                }

                None => {
                    unwrap_result!(el.register(&self.0,
                                                       self.1,
                                                       EventSet::readable(),
                                                       PollOpt::edge()));
                }
            }
        }

        fn as_any(&mut self) -> &mut Any {
            self
        }
    }

    struct Connection(Socket, Token);

    impl Connection {
        fn start(core: &mut Core, el: &mut EventLoop<Core>, token: Token, socket: Socket) {
            unwrap_result!(el.register(&socket,
                                       token,
                                       EventSet::readable(),
                                       PollOpt::edge()));

            let state = Connection(socket, token);
            let _ = core.insert_state(token, Rc::new(RefCell::new(state)));
        }
    }

    impl State for Connection {
        fn ready(&mut self, _: &mut Core, el: &mut EventLoop<Core>, event_set: EventSet) {

            if event_set.is_readable() {
                match unwrap_result!(self.0.read::<Message>()) {
                    Some(Message::BootstrapRequest(..)) => {
                        let public_key = box_::gen_keypair().0;
                        unwrap_result!(self.0.write(el,
                                                    self.1,
                                                    Some((Message::BootstrapResponse(public_key),
                                                          0))));
                    }
                    Some(_) | None => (),
                }
            }

            if event_set.is_writable() {
                unwrap_result!(self.0.write::<Message>(el, self.1, None));
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
    let mut el = unwrap_result!(EventLoop::new());
    let mio_tx = el.channel();

    let _joiner = RaiiThreadJoiner::new(thread::spawn(move || {
        let mut core = Core::new();
        unwrap_result!(el.run(&mut core));
    }));

    let bind_addr = StdSocketAddr::from_str("127.0.0.1:0").expect("Could not parse addr");
    let listener = TcpListener::bind(&bind_addr).expect("Could not bind listener");
    let address = SocketAddr(unwrap_result!(listener.local_addr()));

    unwrap_result!(mio_tx.send(CoreMessage::new(|core, el| {
        broken_peer::Listen::start(core, el, listener)
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

    unwrap_result!(mio_tx.send(CoreMessage::new(|_, el| el.shutdown())));
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

#[test]
/// Properties that message prioritisation needs to maintain:
///
/// 1. Priority 0 should never be dropped.
/// 2. For rest if msg is expired, drop all subsequent messages in all
///    subsequent queues (even if the subsequent queues have msgs that
///    haven't yet expired).
fn message_prioritisation() {
    use std::any::Any;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use common::{Core, CoreTimerId, State, Socket, MAX_MSG_AGE_SECS};
    use mio::EventLoop;
    use mio::{EventSet, PollOpt, Token};
    use mio::tcp::TcpListener;

    struct Listen {
        listener: TcpListener,
        token: Token,
        counter: Cell<u32>,
    }

    impl Listen {
        pub fn start(core: &mut Core, el: &mut EventLoop<Core>,
                     counter: Cell<u32>)
                     -> StdSocketAddr {
            let listener = unwrap_result!(TcpListener::bind(&"127.0.0.1:0"
                                                            .parse().unwrap()));
            let addr = {
                let port = listener.local_addr().unwrap().port();
                format!("127.0.0.1:{}", port).parse().unwrap()
            };
            let token = core.get_new_token();

            unwrap_result!(el.register(&listener, token, EventSet::readable(),
                                       PollOpt::edge()));

            let state = Listen {
                listener: listener,
                token: token,
                counter: counter,
            };

            let _ = core.insert_state(token, Rc::new(RefCell::new(state)));
            addr
        }
    }

    impl State for Listen {
        fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>,
                 _: EventSet) {
            println!("ARE YOU READYYYYYY?");
            match unwrap_result!(self.listener.accept()) {
                Some((socket, _)) => {
                    unwrap_result!(el.deregister(&self.listener));

                    let socket = Socket::wrap(socket);
                    ConnectionB::start(core, el, socket, self.counter.clone());
                }

                None => {
                    unwrap_result!(el.register(&self.listener,
                                               self.token,
                                               EventSet::readable(),
                                               PollOpt::edge()));
                }
            }
        }

        fn as_any(&mut self) -> &mut Any {
            self
        }
    }

    struct ConnectionA {
        socket: Socket,
        token: Token,
        counter: Cell<u32>,
        data_sent: bool,
    }

    impl ConnectionA {
        pub fn start(core: &mut Core, el: &mut EventLoop<Core>,
                     addr: StdSocketAddr, counter: Cell<u32>) {
            let socket = unwrap_result!(Socket::connect(&addr));
            let token = core.get_new_token();

            unwrap_result!(el.register(&socket, token, EventSet::all(),
                                       PollOpt::all()));

            let state = ConnectionA {
                socket: socket,
                token: token,
                counter: counter,
                data_sent: false,
            };
            let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

            let timer_id = CoreTimerId {
                state_id: self.token, timer_id: 1
            };
            let ms = MAX_MSG_AGE_SECS * 1000 * 3 + 4000;
            let _ = unwrap_result!(el.timeout_ms(timer_id, ms));
        }
    }

    impl State for ConnectionA {
        fn ready(&mut self, _core: &mut Core, el: &mut EventLoop<Core>,
                 es: EventSet) {
            if es.is_writable() {
                if self.data_sent {
                    let _ = unwrap_result!(self.socket
                                           .write::<Vec<u32>>(el, self.token,
                                                              None));
                } else {
                    let m = (0..1024).collect::<Vec<u32>>();
                    let m1 = {
                        let mut m = m.clone();
                        *unwrap_option!(m.get_mut(0), "") = 1;
                        m
                    };
                    let _ = unwrap_result!(self.socket
                                           .write(el, self.token,
                                                  Some((m1.clone(), 1))));
                    let mut count = 1;
                    loop {
                        let x = unwrap_result!(self.socket
                                               .write(el, self.token,
                                                      Some((m.clone(), 0))));
                        count += 1;
                        if x == false {
                            break;
                        }
                    }
                    let _ = unwrap_result!(self.socket.write(el, self.token,
                                                             Some((m1, 1))));
                    let _ = unwrap_result!(self.socket.write(el, self.token,
                                                             Some((m, 0))));
                    self.counter.set(count);
                    self.data_sent = true;

                    unwrap_result!(el.deregister(&self.socket));
                    let timer_id = CoreTimerId {
                        state_id: self.token, timer_id: 0
                    };
                    let ms = MAX_MSG_AGE_SECS * 1000 + 3000;
                    let _ = unwrap_result!(el.timeout_ms(timer_id, ms));
                    println!("timeout scheduled");
                }
            }
            if es.is_error() {
                panic!("ConnectionA's socket errored: {:?}",
                       self.socket.take_socket_error());
            }
        }

        fn timeout(&mut self, _core: &mut Core, el: &mut EventLoop<Core>,
                   timer_id: u8) {
            match timer_id {
                0 => (),
                1 => panic!("Test is taking too long. Aborting..."),
                _ => unreachable!(),
            }
            unwrap_result!(el.register(&self.socket, self.token,
                                       EventSet::all(), PollOpt::edge()));
            println!("timeout reached");
        }

        fn as_any(&mut self) -> &mut Any {
            self
        }
    }

    struct ConnectionB {
        socket: Socket,
        token: Token,
        counter: Cell<u32>,
        msgs_read: u32,
    }

    impl ConnectionB {
        pub fn start(core: &mut Core, el: &mut EventLoop<Core>,
                     socket: Socket, counter: Cell<u32>) {
            let token = core.get_new_token();

            unwrap_result!(el.register(&socket, token, EventSet::all(),
                                       PollOpt::edge()));

            let state = ConnectionB {
                socket: socket,
                token: token,
                counter: counter,
                msgs_read: 0,
            };

            let _ = core.insert_state(token, Rc::new(RefCell::new(state)));
        }
    }

    impl State for ConnectionB {
        fn ready(&mut self, _core: &mut Core, el: &mut EventLoop<Core>,
                 es: EventSet) {
            if es.is_readable() {
                while let Some(msg)
                    = unwrap_result!(self.socket.read::<Vec<u32>>()) {
                        let priority_0 = *unwrap_option!(msg.get(0), "") == 0;
                        if self.msgs_read != 0 {
                            assert!(priority_0);
                            self.msgs_read += 1;
                        }
                        if self.counter.get() != 0
                            && self.msgs_read == self.counter.get() {
                                let timer_id = CoreTimerId {
                                    state_id: self.token, timer_id: 0
                                };
                                let ms = MAX_MSG_AGE_SECS * 1000 * 2;
                                let _ = unwrap_result!(el.timeout_ms(timer_id,
                                                                     ms));
                                return;
                        }
                }
                println!("UPDATE {} {}", self.msgs_read, self.counter.get());
            }
            unwrap_result!(el.reregister(&self.socket, self.token,
                                         EventSet::all(), PollOpt::edge()));
        }

        fn timeout(&mut self, _core: &mut Core, el: &mut EventLoop<Core>,
                   timer_id: u8) {
            assert_eq!(timer_id, 0);
            el.shutdown();
        }

        fn as_any(&mut self) -> &mut Any {
            self
        }
    }

    let mut el = EventLoop::new().unwrap();
    let mut core = Core::new();
    let counter = Cell::new(0);
    {
        let addr = Listen::start(&mut core, &mut el, counter.clone());
        ConnectionA::start(&mut core, &mut el, addr, counter);
    }
    unwrap_result!(el.run(&mut core));
}
