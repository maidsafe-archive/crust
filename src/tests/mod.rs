// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#[macro_use]
pub mod utils;

pub use self::utils::{
    gen_config, get_event_sender, rand_peer_id_and_enc_sk, test_service, timebomb,
};

use crate::common::{CrustUser, PeerInfo};
use crate::main::{Config, Event, Service};
use crate::PeerId;
use hamcrest2::prelude::*;
use mio;
use rand;
use safe_crypto::{gen_encrypt_keypair, PublicEncryptKey};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn localhost_contact_info(port: u16, pk: PublicEncryptKey) -> PeerInfo {
    use std::net::IpAddr;
    let addr = SocketAddr::new(unwrap!(IpAddr::from_str("127.0.0.1")), port);
    PeerInfo::new(addr, pk)
}

fn gen_service_discovery_port() -> u16 {
    const BASE: u16 = 40_000;
    static COUNTER: AtomicUsize = ATOMIC_USIZE_INIT;

    BASE + COUNTER.fetch_add(1, Ordering::Relaxed) as u16
}

mod connect {
    use super::*;

    #[test]
    fn successfully_connected_peer_contacts_are_cached() {
        let (mut service1, event_rx1) = test_service();
        let (service2, event_rx2) = test_service();

        unwrap!(service1.start_listening_tcp());
        expect_event!(event_rx1, Event::ListenerStarted(_port) => ());
        unwrap!(service1.set_ext_reachability_test(false));
        let uid1 = service1.id();

        let (ci_tx1, ci_rx1) = mpsc::channel();

        let token = rand::random();
        service1.prepare_connection_info(token);
        let ci1 = expect_event!(event_rx1, Event::ConnectionInfoPrepared(res) => {
            assert_eq!(res.result_token, token);
            unwrap!(res.result)
        });
        unwrap!(ci_tx1.send(ci1.to_pub_connection_info()));

        let token = rand::random();
        service2.prepare_connection_info(token);
        let ci2 = expect_event!(event_rx2, Event::ConnectionInfoPrepared(res) => {
            assert_eq!(res.result_token, token);
            unwrap!(res.result)
        });
        let pub_ci1 = unwrap!(ci_rx1.recv());
        let pub_key1 = pub_ci1.id.pub_enc_key;
        let expected_conns: Vec<PeerInfo> = pub_ci1
            .for_direct
            .iter()
            .map(|addr| PeerInfo::new(*addr, pub_key1))
            .collect();

        unwrap!(service2.connect(ci2, pub_ci1));
        expect_event!(event_rx2, Event::ConnectSuccess(id) => {
            assert_eq!(id, uid1);
        });

        let cached_peers = unwrap!(service2.bootstrap_cached_peers());
        assert_that!(&expected_conns, contains(cached_peers));
    }

    #[test]
    fn when_external_reachability_is_disabled_successfully_connects_on_localhost() {
        let (mut service1, event_rx1) = test_service();
        let (service2, event_rx2) = test_service();

        unwrap!(service1.start_listening_tcp());
        expect_event!(event_rx1, Event::ListenerStarted(_port) => ());
        unwrap!(service1.set_ext_reachability_test(false));
        let uid1 = service1.id();

        let (ci_tx1, ci_rx1) = mpsc::channel();

        let token = rand::random();
        service1.prepare_connection_info(token);
        let ci1 = expect_event!(event_rx1, Event::ConnectionInfoPrepared(res) => {
            assert_eq!(res.result_token, token);
            unwrap!(res.result)
        });
        unwrap!(ci_tx1.send(ci1.to_pub_connection_info()));

        let token = rand::random();
        service2.prepare_connection_info(token);
        let ci2 = expect_event!(event_rx2, Event::ConnectionInfoPrepared(res) => {
            assert_eq!(res.result_token, token);
            unwrap!(res.result)
        });
        let pub_ci1 = unwrap!(ci_rx1.recv());

        unwrap!(service2.connect(ci2, pub_ci1));
        expect_event!(event_rx2, Event::ConnectSuccess(id) => {
            assert_eq!(id, uid1);
        });
    }

    #[test]
    fn when_external_reachability_is_enabled_fails_to_connect_on_localhost() {
        let (mut service1, event_rx1) = test_service();
        let (service2, event_rx2) = test_service();

        unwrap!(service1.start_listening_tcp());
        expect_event!(event_rx1, Event::ListenerStarted(_port) => ());
        unwrap!(service1.set_ext_reachability_test(true));
        let uid1 = service1.id();

        let (ci_tx1, ci_rx1) = mpsc::channel();

        let token = rand::random();
        service1.prepare_connection_info(token);
        let ci1 = expect_event!(event_rx1, Event::ConnectionInfoPrepared(res) => {
            assert_eq!(res.result_token, token);
            unwrap!(res.result)
        });
        unwrap!(ci_tx1.send(ci1.to_pub_connection_info()));

        let token = rand::random();
        service2.prepare_connection_info(token);
        let ci2 = expect_event!(event_rx2, Event::ConnectionInfoPrepared(res) => {
            assert_eq!(res.result_token, token);
            unwrap!(res.result)
        });
        let pub_ci1 = unwrap!(ci_rx1.recv());

        unwrap!(service2.connect(ci2, pub_ci1));
        expect_event!(event_rx2, Event::ConnectFailure(id) => {
            assert_eq!(id, uid1);
        });
    }
}

#[test]
fn bootstrap_two_services_and_exchange_messages() {
    let (mut service0, event_rx0) = test_service();
    unwrap!(service0.start_listening_tcp());

    let port0 = expect_event!(event_rx0, Event::ListenerStarted(port) => port);
    unwrap!(service0.set_accept_bootstrap(true));

    let mut config1 = gen_config();
    config1.hard_coded_contacts = vec![localhost_contact_info(port0, service0.pub_key())];

    let (event_tx1, event_rx1) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service1 = unwrap!(Service::with_config(event_tx1, config1, peer_id, peer_sk));

    unwrap!(service1.start_bootstrap(HashSet::new(), CrustUser::Client));

    let peer_id0 = expect_event!(event_rx1, Event::BootstrapConnect(peer_id, _) => peer_id);
    assert_eq!(peer_id0, service0.id());

    let peer_id1 = expect_event!(event_rx0,
                                 Event::BootstrapAccept(peer_id, CrustUser::Client) => peer_id);
    assert_eq!(peer_id1, service1.id());

    let message0 = b"hello from 0".to_vec();
    unwrap!(service0.send(&peer_id1, message0.clone(), 0));

    expect_event!(event_rx1, Event::NewMessage(peer_id, CrustUser::Node, data) => {
        assert_eq!(peer_id, peer_id0);
        assert_eq!(data, message0);
    });

    let message1 = b"hello from 1".to_vec();
    unwrap!(service1.send(&peer_id0, message1.clone(), 0));

    expect_event!(event_rx0, Event::NewMessage(peer_id, CrustUser::Client, data) => {
        assert_eq!(peer_id, peer_id1);
        assert_eq!(data, message1);
    });
}

// Note: if this test fails, make sure that a firewall on your system allows UDP broadcasts
#[test]
fn bootstrap_two_services_using_service_discovery() {
    let mut config0 = gen_config();
    let service0_discovery_port = gen_service_discovery_port();
    config0.service_discovery_listener_port = Some(service0_discovery_port);

    let (event_tx0, event_rx0) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service0 = unwrap!(Service::with_config(event_tx0, config0, peer_id, peer_sk));

    let (event_tx1, event_rx1) = get_event_sender();
    let mut config1 = gen_config();
    config1.service_discovery_listener_port = Some(gen_service_discovery_port());
    config1.service_discovery_port = Some(service0_discovery_port);
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service1 = unwrap!(Service::with_config(event_tx1, config1, peer_id, peer_sk));

    unwrap!(service1.start_listening_tcp());
    let _ = expect_event!(event_rx1, Event::ListenerStarted(port) => port);

    service0.start_service_discovery();
    service0.set_service_discovery_listen(true);
    unwrap!(service0.start_listening_tcp());

    expect_event!(event_rx0, Event::ListenerStarted(_port));
    unwrap!(service0.set_accept_bootstrap(true));

    service1.start_service_discovery();
    unwrap!(service1.start_bootstrap(HashSet::new(), CrustUser::Client));

    let peer_id0 = expect_event!(event_rx1, Event::BootstrapConnect(peer_id, _) => peer_id);
    assert_eq!(peer_id0, service0.id());

    let peer_id1 = expect_event!(event_rx0, Event::BootstrapAccept(peer_id, _) => peer_id);
    assert_eq!(peer_id1, service1.id());
}

#[test]
fn bootstrap_with_multiple_contact_endpoints() {
    use std::net::TcpListener;

    let (event_tx0, event_rx0) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service0 = unwrap!(Service::with_config(
        event_tx0,
        Config::default(),
        peer_id,
        peer_sk
    ));
    unwrap!(service0.start_listening_tcp());
    let port = expect_event!(event_rx0, Event::ListenerStarted(port) => port);
    unwrap!(service0.set_accept_bootstrap(true));
    let valid_address = localhost_contact_info(port, service0.pub_key());

    let deaf_listener = unwrap!(TcpListener::bind("127.0.0.1:0"));
    let invalid_address = PeerInfo::new(unwrap!(deaf_listener.local_addr()), service0.pub_key());;

    let mut config1 = gen_config();
    config1.hard_coded_contacts = vec![invalid_address, valid_address];

    let (event_tx1, event_rx1) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service1 = unwrap!(Service::with_config(event_tx1, config1, peer_id, peer_sk));
    unwrap!(service1.start_bootstrap(HashSet::new(), CrustUser::Client));

    unwrap!(service1.start_listening_tcp());
    let _ = expect_event!(event_rx1, Event::ListenerStarted(port) => port);

    let peer_id0 = expect_event!(event_rx1, Event::BootstrapConnect(peer_id, _) => peer_id);
    assert_eq!(peer_id0, service0.id());

    let peer_id1 = expect_event!(event_rx0, Event::BootstrapAccept(peer_id, _) => peer_id);
    assert_eq!(peer_id1, service1.id());
}

#[test]
fn bootstrap_with_skipped_external_reachability_test() {
    let config = Config::default();
    let (event_tx0, event_rx0) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service0 = unwrap!(Service::with_config(event_tx0, config, peer_id, peer_sk));
    unwrap!(service0.start_listening_tcp());
    let port = expect_event!(event_rx0, Event::ListenerStarted(port) => port);
    unwrap!(service0.set_accept_bootstrap(true));
    unwrap!(service0.set_ext_reachability_test(false));

    let mut config1 = gen_config();
    config1.hard_coded_contacts = vec![localhost_contact_info(port, service0.pub_key())];

    let (event_tx1, event_rx1) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service1 = unwrap!(Service::with_config(event_tx1, config1, peer_id, peer_sk));
    unwrap!(service1.start_bootstrap(HashSet::new(), CrustUser::Node));

    let peer_id0 = expect_event!(event_rx1, Event::BootstrapConnect(peer_id, _) => peer_id);
    assert_eq!(peer_id0, service0.id());

    let peer_id1 = expect_event!(event_rx0, Event::BootstrapAccept(peer_id, _) => peer_id);
    assert_eq!(peer_id1, service1.id());
}

#[test]
fn bootstrap_with_blacklist() {
    use std::net::TcpListener;

    let (event_tx0, event_rx0) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service0 = unwrap!(Service::with_config(
        event_tx0,
        Config::default(),
        peer_id,
        peer_sk
    ));
    unwrap!(service0.start_listening_tcp());
    let port = expect_event!(event_rx0, Event::ListenerStarted(port) => port);
    unwrap!(service0.set_accept_bootstrap(true));
    let valid_address = localhost_contact_info(port, service0.pub_key());

    let blacklisted_listener = unwrap!(TcpListener::bind("127.0.0.1:0"));
    let blacklisted_address = PeerInfo::new(
        unwrap!(blacklisted_listener.local_addr()),
        service0.pub_key(),
    );

    let mut config1 = gen_config();
    config1.hard_coded_contacts = vec![blacklisted_address, valid_address];

    let (event_tx1, event_rx1) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service1 = unwrap!(Service::with_config(event_tx1, config1, peer_id, peer_sk));
    let mut blacklist = HashSet::new();
    let _ = blacklist.insert(blacklisted_address.addr);
    unwrap!(service1.start_bootstrap(blacklist, CrustUser::Client));

    unwrap!(service1.start_listening_tcp());
    let _ = expect_event!(event_rx1, Event::ListenerStarted(port) => port);

    let peer_id0 = expect_event!(event_rx1, Event::BootstrapConnect(peer_id, _) => peer_id);
    assert_eq!(peer_id0, service0.id());

    let peer_id1 = expect_event!(event_rx0, Event::BootstrapAccept(peer_id, _) => peer_id);
    assert_eq!(peer_id1, service1.id());

    let blacklisted_listener = unwrap!(mio::net::TcpListener::from_std(blacklisted_listener));
    thread::sleep(Duration::from_secs(5));
    // TODO See if these are doing the right thing - wait for Adam to explain as he might have
    // written this test case. Also check the similar one below.
    let res = blacklisted_listener.accept();
    assert!(res.is_err())
}

#[test]
fn bootstrap_fails_only_blacklisted_contact() {
    use std::net::TcpListener;

    let blacklisted_listener = unwrap!(TcpListener::bind("127.0.0.1:0"));
    let (pk, _sk) = gen_encrypt_keypair();
    let blacklisted_address = PeerInfo::new(unwrap!(blacklisted_listener.local_addr()), pk);

    let mut config = gen_config();
    config.hard_coded_contacts = vec![blacklisted_address];
    let (event_tx, event_rx) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service = unwrap!(Service::with_config(event_tx, config, peer_id, peer_sk));

    let mut blacklist = HashSet::new();
    let _ = blacklist.insert(blacklisted_address.addr);
    unwrap!(service.start_bootstrap(blacklist, CrustUser::Client));

    expect_event!(event_rx, Event::BootstrapFailed);

    let blacklisted_listener = unwrap!(mio::net::TcpListener::from_std(blacklisted_listener));
    thread::sleep(Duration::from_secs(5));
    let res = blacklisted_listener.accept();
    assert!(res.is_err())
}

#[test]
fn bootstrap_fails_if_there_are_no_contacts() {
    let config = gen_config();
    let (event_tx, event_rx) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service = unwrap!(Service::with_config(event_tx, config, peer_id, peer_sk));

    unwrap!(service.start_bootstrap(HashSet::new(), CrustUser::Client));
    expect_event!(event_rx, Event::BootstrapFailed);
}

#[test]
fn bootstrap_timeouts_if_there_are_only_invalid_contacts() {
    use std::net::TcpListener;

    let deaf_listener = unwrap!(TcpListener::bind("127.0.0.1:0"));
    let (pk, _sk) = gen_encrypt_keypair();
    let address = PeerInfo::new(unwrap!(deaf_listener.local_addr()), pk);

    let mut config = gen_config();
    config.hard_coded_contacts = vec![address];

    let (event_tx, event_rx) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service = unwrap!(Service::with_config(event_tx, config, peer_id, peer_sk));

    unwrap!(service.start_bootstrap(HashSet::new(), CrustUser::Client));
    expect_event!(event_rx, Event::BootstrapFailed);
}

#[test]
fn drop_disconnects() {
    let config_0 = gen_config();
    let (event_tx_0, event_rx_0) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service_0 = unwrap!(Service::with_config(event_tx_0, config_0, peer_id, peer_sk));

    unwrap!(service_0.start_listening_tcp());
    let port = expect_event!(event_rx_0, Event::ListenerStarted(port) => port);
    unwrap!(service_0.set_accept_bootstrap(true));

    let mut config_1 = gen_config();
    config_1.hard_coded_contacts = vec![localhost_contact_info(port, service_0.pub_key())];

    let (event_tx_1, event_rx_1) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service_1 = unwrap!(Service::with_config(event_tx_1, config_1, peer_id, peer_sk));

    unwrap!(service_1.start_bootstrap(HashSet::new(), CrustUser::Client));

    let peer_id_0 = expect_event!(event_rx_1, Event::BootstrapConnect(peer_id, _) => peer_id);
    expect_event!(event_rx_0, Event::BootstrapAccept(_peer_id, _));

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
    use super::*;
    use crate::common::{Core, Message, State};
    use mio::net::TcpListener;
    use mio::{Poll, PollOpt, Ready, Token};
    use safe_crypto::SecretEncryptKey;
    use socket_collection::{DecryptContext, EncryptContext, TcpSock};
    use std::any::Any;
    use std::cell::RefCell;
    use std::rc::Rc;

    pub struct Listen {
        listener: TcpListener,
        token: Token,
        our_id: PeerId,
        our_sk: SecretEncryptKey,
    }

    impl Listen {
        pub fn start(
            core: &mut Core<()>,
            poll: &Poll,
            listener: TcpListener,
            our_id: PeerId,
            our_sk: SecretEncryptKey,
        ) {
            let token = core.get_new_token();

            unwrap!(poll.register(&listener, token, Ready::readable(), PollOpt::edge()));

            let state = Listen {
                listener,
                token,
                our_id,
                our_sk,
            };
            let _ = core.insert_state(token, Rc::new(RefCell::new(state)));
        }
    }

    impl State<()> for Listen {
        fn ready(&mut self, core: &mut Core<()>, poll: &Poll, _: Ready) {
            let (socket, _) = unwrap!(self.listener.accept());
            unwrap!(poll.deregister(&self.listener));

            let mut socket = TcpSock::wrap(socket);
            unwrap!(socket.set_decrypt_ctx(DecryptContext::anonymous_decrypt(
                self.our_id.pub_enc_key,
                self.our_sk.clone()
            )));
            Connection::start(core, poll, self.token, socket, self.our_id, &self.our_sk);
        }

        fn as_any(&mut self) -> &mut Any {
            self
        }
    }

    struct Connection {
        socket: TcpSock,
        token: Token,
        our_id: PeerId,
        our_sk: SecretEncryptKey,
    }

    impl Connection {
        fn start(
            core: &mut Core<()>,
            poll: &Poll,
            token: Token,
            socket: TcpSock,
            our_id: PeerId,
            our_sk: &SecretEncryptKey,
        ) {
            unwrap!(poll.register(&socket, token, Ready::readable(), PollOpt::edge()));

            let state = Connection {
                socket,
                token,
                our_id,
                our_sk: our_sk.clone(),
            };
            let _ = core.insert_state(token, Rc::new(RefCell::new(state)));
        }
    }

    impl State<()> for Connection {
        fn ready(&mut self, core: &mut Core<()>, poll: &Poll, kind: Ready) {
            if kind.is_readable() {
                match self.socket.read::<Message>() {
                    Ok(Some(Message::BootstrapRequest(their_id, _, _))) => {
                        let shared_key = self.our_sk.shared_secret(&their_id.pub_enc_key);
                        unwrap!(self
                            .socket
                            .set_encrypt_ctx(EncryptContext::authenticated(shared_key)));
                        let _ = unwrap!(self
                            .socket
                            .write(Some((Message::BootstrapGranted(self.our_id), 0))));
                    }
                    Ok(Some(_)) | Ok(None) => (),
                    Err(_) => self.terminate(core, poll),
                }
            }

            if kind.is_writable() {
                let _ = unwrap!(self.socket.write::<Message>(None));
            }
        }

        fn terminate(&mut self, core: &mut Core<()>, poll: &Poll) {
            let _ = core.remove_state(self.token);
            unwrap!(poll.deregister(&self.socket));
        }

        fn as_any(&mut self) -> &mut Any {
            self
        }
    }
}

#[test]
fn drop_peer_when_no_message_received_within_inactivity_period() {
    use self::broken_peer;
    use crate::common::{spawn_event_loop, CoreMessage};
    use mio::net::TcpListener;

    // Spin up the non-responsive peer.
    let el = unwrap!(spawn_event_loop(0, None, || ()));

    let bind_addr = unwrap!(SocketAddr::from_str("127.0.0.1:0"), "Could not parse addr");
    let listener = unwrap!(TcpListener::bind(&bind_addr), "Could not bind listener");
    let (listener_id, listener_sk) = rand_peer_id_and_enc_sk();
    let address = PeerInfo::new(unwrap!(listener.local_addr()), listener_id.pub_enc_key);

    unwrap!(el.send(CoreMessage::new(move |core, poll| {
        broken_peer::Listen::start(core, poll, listener, listener_id, listener_sk)
    })));

    // Spin up normal service that will connect to the above guy.
    let mut config = gen_config();
    config.hard_coded_contacts = vec![address];

    let (event_tx, event_rx) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service = unwrap!(Service::with_config(event_tx, config, peer_id, peer_sk));

    unwrap!(service.start_bootstrap(HashSet::new(), CrustUser::Client));
    let peer_id = expect_event!(event_rx, Event::BootstrapConnect(peer_id, _) => peer_id);

    // The peer should drop after inactivity.
    expect_event!(event_rx, Event::LostPeer(lost_peer_id) => {
        assert_eq!(lost_peer_id, peer_id)
    });
}

#[test]
fn do_not_drop_peer_even_when_no_data_messages_are_exchanged_within_inactivity_period() {
    use crate::main::INACTIVITY_TIMEOUT_MS;
    use std::thread;
    use std::time::Duration;

    let config0 = gen_config();
    let (event_tx0, event_rx0) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service0 = unwrap!(Service::with_config(event_tx0, config0, peer_id, peer_sk));

    unwrap!(service0.start_listening_tcp());
    let port0 = expect_event!(event_rx0, Event::ListenerStarted(port) => port);
    unwrap!(service0.set_accept_bootstrap(true));

    let mut config1 = gen_config();
    config1.hard_coded_contacts = vec![localhost_contact_info(port0, service0.pub_key())];

    let (event_tx1, event_rx1) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let mut service1 = unwrap!(Service::with_config(event_tx1, config1, peer_id, peer_sk));

    unwrap!(service1.start_bootstrap(HashSet::new(), CrustUser::Client));
    expect_event!(event_rx1, Event::BootstrapConnect(_peer_id, _));
    expect_event!(event_rx0, Event::BootstrapAccept(_peer_id, _));

    thread::sleep(Duration::from_millis(2 * INACTIVITY_TIMEOUT_MS));

    if let Ok(Event::LostPeer(..)) = event_rx0.try_recv() {
        panic!("peer lost unexpectedly");
    }

    if let Ok(Event::LostPeer(..)) = event_rx1.try_recv() {
        panic!("peer lost unexpectedly");
    }
}
