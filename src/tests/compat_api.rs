// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use compat::{self, Event};
use config::{DevConfigSettings, PeerInfo};
use env_logger;
use net::peer::INACTIVITY_TIMEOUT_MS;
use priv_prelude::*;
use rand;
use std;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use util::{self, crust_event_channel};

// Receive an event from the given receiver and asserts that it matches the
// given pattern.
macro_rules! expect_event {
    ($rx:expr, $pattern:pat) => {
        match unwrap!($rx.recv_timeout(::std::time::Duration::from_secs(30))) {
            $pattern => (),
            e => panic!("unexpected event {:?}", e),
        }
    };

    ($rx:expr, $pattern:pat => $arm:expr) => {
        match unwrap!($rx.recv_timeout(::std::time::Duration::from_secs(30))) {
            $pattern => $arm,
            e => panic!("unexpected event {:?}", e),
        }
    };
}

fn service_with_config(config: ConfigFile) -> (compat::Service, Receiver<Event>) {
    let (event_tx, event_rx) = crust_event_channel();
    let sk = SecretKeys::new();
    let service = unwrap!(compat::Service::with_config(event_tx, config, sk));
    (service, event_rx)
}

fn service() -> (compat::Service, Receiver<Event>) {
    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0"), utp_addr!("0.0.0.0:0")];
    service_with_config(config)
}

fn exchange_messages(
    service0: &compat::Service,
    service1: &compat::Service,
    event_rx0: &Receiver<Event>,
    event_rx1: &Receiver<Event>,
    kind1: CrustUser,
) {
    let uid0 = service0.public_id();
    let uid1 = service1.public_id();

    let msg0 = b"hello from service0";
    let msg1 = b"hello from service1";
    unwrap!(service0.send(&uid1, msg0[..].to_owned(), 0));
    unwrap!(service1.send(&uid0, msg1[..].to_owned(), 0));

    expect_event!(event_rx0, Event::NewMessage(id, kind, data) => {
        assert_eq!(data, msg1);
        assert_eq!(id, uid1);
        assert_eq!(kind, kind1);
    });
    expect_event!(event_rx1, Event::NewMessage(id, CrustUser::Node, data) => {
        assert_eq!(data, msg0);
        assert_eq!(id, uid0);
    });
}

fn bootstrap_and_exchange(
    service0: &compat::Service,
    service1: &compat::Service,
    event_rx0: &Receiver<Event>,
    event_rx1: &Receiver<Event>,
    kind1: CrustUser,
) {
    let uid0 = service0.public_id();
    let uid1 = service1.public_id();

    unwrap!(service1.start_bootstrap(HashSet::new(), kind1));

    loop {
        expect_event!(event_rx0, Event::BootstrapAccept(id, kind) => {
            if id == uid1 && kind == kind1 {
                break;
            }
        });
    }

    expect_event!(event_rx1, Event::BootstrapConnect(id, _) => {
        assert_eq!(id, uid0);
    });

    exchange_messages(service0, service1, event_rx0, event_rx1, kind1);
}

/// Returns two services - we need to hold them until our test cases are finished.
fn bootstrap_and_do_nothing(
    listener_addr: PaAddr,
    heartbeats_enabled: bool,
) -> (
    Receiver<Event>,
    Receiver<Event>,
    compat::Service,
    compat::Service,
) {
    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![listener_addr];
    let (mut service1, event_rx1) = service_with_config(config);
    if !heartbeats_enabled {
        service1.disable_peer_heartbeats();
    }

    unwrap!(service1.start_listening());
    let service1_addr = expect_event!(event_rx1, Event::ListenerStarted(addr) => addr);
    let service1_addr = service1_addr.unspecified_to_localhost();
    unwrap!(service1.set_accept_bootstrap(true));

    let (event_tx2, event_rx2) = crust_event_channel();
    let config2 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config2.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
    unwrap!(config2.write()).hard_coded_contacts =
        vec![PeerInfo::new(service1_addr, service1.public_id())];
    let sk2 = SecretKeys::new();
    let mut service2 = unwrap!(compat::Service::with_config(
        event_tx2,
        config2,
        sk2.clone()
    ));
    if !heartbeats_enabled {
        service2.disable_peer_heartbeats();
    }

    unwrap!(service2.start_bootstrap(HashSet::new(), CrustUser::Client));
    expect_event!(event_rx2, Event::BootstrapConnect(_peer_id, _));
    expect_event!(event_rx1, Event::BootstrapAccept(_peer_id, _));

    (event_rx1, event_rx2, service1, service2)
}

#[test]
fn start_two_services_exchange_data() {
    let _ = env_logger::init();

    let (service0, event_rx0) = service();
    let (service1, event_rx1) = service();

    unwrap!(service0.start_listening());
    let _addr = expect_event!(event_rx0, Event::ListenerStarted(addr0) => addr0);
    let addr0 = expect_event!(event_rx0, Event::ListenerStarted(addr0) => addr0);

    unwrap!(service1.start_listening());
    let _addr = expect_event!(event_rx1, Event::ListenerStarted(addr1) => addr1);
    let addr1 = expect_event!(event_rx1, Event::ListenerStarted(addr1) => addr1);

    assert_ne!(addr0, addr1);

    const NUM_MESSAGES: usize = 100;
    // TODO(povilas): have a test with bigger data buffer sizes (>2MB). Such tests might reveal
    // other issues.
    const MAX_DATA_SIZE: usize = 512;

    let uid0 = service0.public_id();
    let uid1 = service1.public_id();

    let data0 = (0..NUM_MESSAGES)
        .map(|_| util::random_vec(MAX_DATA_SIZE))
        .collect::<Vec<_>>();
    let data0_compare = data0.clone();

    let data1 = (0..NUM_MESSAGES)
        .map(|_| util::random_vec(MAX_DATA_SIZE))
        .collect::<Vec<_>>();
    let data1_compare = data1.clone();

    let (ci_tx0, ci_rx0) = mpsc::channel();
    let (ci_tx1, ci_rx1) = mpsc::channel();

    let j0 = thread::spawn(move || {
        let token = rand::random();
        service0.prepare_connection_info(token);
        let ci0 = expect_event!(event_rx0, Event::ConnectionInfoPrepared(res) => {
            assert_eq!(res.result_token, token);
            unwrap!(res.result)
        });
        unwrap!(ci_tx0.send(ci0.clone()));
        let pub_ci1 = unwrap!(ci_rx1.recv());

        unwrap!(service0.connect(ci0, pub_ci1));
        expect_event!(event_rx0, Event::ConnectSuccess(id) => {
            assert_eq!(id, uid1);
        });

        for payload in data0 {
            unwrap!(service0.send(&uid1, payload, 0));
        }

        let mut i = 0;
        let data1_recv = {
            event_rx0
                .into_iter()
                .take(NUM_MESSAGES)
                .map(|msg| {
                    i += 1;
                    match msg {
                        Event::NewMessage(uid, _user, data) => {
                            assert_eq!(uid, uid1);
                            data
                        }
                        e => panic!("unexpected event: {:?}", e),
                    }
                })
                .collect::<Vec<_>>()
        };

        assert_eq!(data1_recv, data1_compare);
        service0
    });
    let j1 = thread::spawn(move || {
        let token = rand::random();
        service1.prepare_connection_info(token);
        let ci1 = expect_event!(event_rx1, Event::ConnectionInfoPrepared(res) => {
            assert_eq!(res.result_token, token);
            unwrap!(res.result)
        });
        unwrap!(ci_tx1.send(ci1.clone()));
        let pub_ci0 = unwrap!(ci_rx0.recv());

        unwrap!(service1.connect(ci1, pub_ci0));
        expect_event!(event_rx1, Event::ConnectSuccess(id) => {
            assert_eq!(id, uid0);
        });

        for payload in data1 {
            unwrap!(service1.send(&uid0, payload, 0));
        }

        let mut i = 0;
        let data0_recv = {
            event_rx1
                .into_iter()
                .take(NUM_MESSAGES)
                .map(|msg| {
                    i += 1;
                    match msg {
                        Event::NewMessage(uid, _user, data) => {
                            assert_eq!(uid, uid0);
                            data
                        }
                        e => panic!("unexpected event: {:?}", e),
                    }
                })
                .collect::<Vec<_>>()
        };

        assert_eq!(data0_recv, data0_compare);
        service1
    });

    let service0 = unwrap!(j0.join());
    let service1 = unwrap!(j1.join());
    drop(service0);
    drop(service1);
}

mod bootstrap {
    use super::*;

    fn bootstrap_using_hard_coded_contacts(listen_addr: PaAddr) {
        let _ = env_logger::init();

        let config = unwrap!(ConfigFile::new_temporary());
        unwrap!(config.write()).listen_addresses = vec![listen_addr];
        let (service0, event_rx0) = service_with_config(config);

        unwrap!(service0.start_listening());
        let addr0 = expect_event!(event_rx0, Event::ListenerStarted(addr0) => addr0);
        let addr0 = addr0.unspecified_to_localhost();

        unwrap!(service0.set_accept_bootstrap(true));

        let (event_tx1, event_rx1) = crust_event_channel();
        let config1 = unwrap!(ConfigFile::new_temporary());
        unwrap!(config1.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        unwrap!(config1.write()).hard_coded_contacts =
            vec![PeerInfo::new(addr0, service0.public_id())];
        let sk1 = SecretKeys::new();
        let service1 = unwrap!(compat::Service::with_config(
            event_tx1,
            config1,
            sk1.clone()
        ));

        bootstrap_and_exchange(
            &service0,
            &service1,
            &event_rx0,
            &event_rx1,
            CrustUser::Client,
        );

        drop(service1);
        expect_event!(event_rx0, Event::LostPeer(id) => {
            assert_eq!(&id, sk1.public_keys());
        });

        expect_event!(event_rx1, Event::LostPeer(id) => {
            assert_eq!(id, service0.public_id());
        });
    }

    #[test]
    fn using_hard_coded_tcp_contacts() {
        bootstrap_using_hard_coded_contacts(tcp_addr!("0.0.0.0:0"));
    }

    #[test]
    fn using_hard_coded_utp_contacts() {
        bootstrap_using_hard_coded_contacts(utp_addr!("0.0.0.0:0"));
    }

    #[test]
    fn using_service_discovery() {
        let _ = env_logger::init();

        let (service0, event_rx0) = service();

        unwrap!(service0.start_listening());
        let _port0 = expect_event!(event_rx0, Event::ListenerStarted(port0) => port0);
        let _port0 = expect_event!(event_rx0, Event::ListenerStarted(port0) => port0);

        unwrap!(service0.set_accept_bootstrap(true));
        service0.start_service_discovery();
        service0.set_service_discovery_listen(true);

        let (service1, event_rx1) = service();
        service1.start_service_discovery();
        bootstrap_and_exchange(
            &service0,
            &service1,
            &event_rx0,
            &event_rx1,
            CrustUser::Client,
        );
    }

    #[test]
    fn with_multiple_contact_endpoints() {
        let _ = env_logger::init();

        let (service0, event_rx0) = service();

        unwrap!(service0.start_listening());
        let _addr = expect_event!(event_rx0, Event::ListenerStarted(addr0) => addr0);
        let addr0 = expect_event!(event_rx0, Event::ListenerStarted(addr0) => addr0);

        unwrap!(service0.set_accept_bootstrap(true));

        let valid_address = addr0.unspecified_to_localhost();

        let mut addresses = Vec::new();
        let mut listeners = Vec::new();
        for _ in 0..10 {
            let listener = unwrap!(::std::net::TcpListener::bind(&addr!("127.0.0.1:0")));
            let addr = unwrap!(listener.local_addr());
            let addr = PaAddr::Tcp(addr).unspecified_to_localhost();
            addresses.push(PeerInfo::with_rand_key(addr));
            listeners.push(listener);
        }

        addresses.push(PeerInfo::new(valid_address, service0.public_id()));

        let config1 = unwrap!(ConfigFile::new_temporary());
        unwrap!(config1.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        unwrap!(config1.write()).hard_coded_contacts = addresses;
        let (service1, event_rx1) = service_with_config(config1);

        bootstrap_and_exchange(
            &service0,
            &service1,
            &event_rx0,
            &event_rx1,
            CrustUser::Client,
        );
    }

    #[test]
    fn with_disable_external_reachability() {
        let _ = env_logger::init();

        let (event_tx0, event_rx0) = crust_event_channel();
        let config0 = unwrap!(ConfigFile::new_temporary());
        let mut dev_cfg = DevConfigSettings::default();
        dev_cfg.disable_external_reachability_requirement = true;
        unwrap!(config0.write()).dev = Some(dev_cfg);
        unwrap!(config0.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0")];
        let sk0 = SecretKeys::new();
        let service0 = unwrap!(compat::Service::with_config(event_tx0, config0, sk0));

        unwrap!(service0.start_listening());
        let addr0 = expect_event!(event_rx0, Event::ListenerStarted(addr0) => addr0);

        unwrap!(service0.set_accept_bootstrap(true));

        let config1 = unwrap!(ConfigFile::new_temporary());
        unwrap!(config1.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        unwrap!(config1.write()).hard_coded_contacts = vec![PeerInfo::new(
            addr0.unspecified_to_localhost(),
            service0.public_id(),
        )];
        let (service1, event_rx1) = service_with_config(config1);

        bootstrap_and_exchange(
            &service0,
            &service1,
            &event_rx0,
            &event_rx1,
            CrustUser::Node,
        );
    }

    fn bootstrap_with_blacklist(listen_addr: PaAddr) {
        let _ = env_logger::init();

        let config = unwrap!(ConfigFile::new_temporary());
        unwrap!(config.write()).listen_addresses = vec![listen_addr];
        let (service0, event_rx0) = service_with_config(config);

        unwrap!(service0.start_listening());
        let addr0 = expect_event!(event_rx0, Event::ListenerStarted(addr0) => addr0);

        unwrap!(service0.set_accept_bootstrap(true));

        let valid_addr = addr0.unspecified_to_localhost();

        let blacklisted_listener = unwrap!(std::net::TcpListener::bind(addr!("0.0.0.0:0")));
        let blacklisted_addr = unwrap!(blacklisted_listener.local_addr());
        let blacklisted_addr = PaAddr::Tcp(blacklisted_addr).unspecified_to_localhost();
        unwrap!(blacklisted_listener.set_nonblocking(true));

        let config1 = unwrap!(ConfigFile::new_temporary());
        unwrap!(config1.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        unwrap!(config1.write()).hard_coded_contacts = vec![
            PeerInfo::new(valid_addr, service0.public_id()),
            PeerInfo::with_rand_key(blacklisted_addr),
        ];
        let (service1, event_rx1) = service_with_config(config1);

        let uid0 = service0.public_id();
        let uid1 = service1.public_id();

        unwrap!(service1.start_bootstrap(hashset!{blacklisted_addr}, CrustUser::Client));

        expect_event!(event_rx0, Event::BootstrapAccept(id, CrustUser::Client) => {
            assert_eq!(id, uid1);
        });

        expect_event!(event_rx1, Event::BootstrapConnect(id, _) => {
            assert_eq!(id, uid0);
        });

        exchange_messages(
            &service0,
            &service1,
            &event_rx0,
            &event_rx1,
            CrustUser::Client,
        );

        thread::sleep(Duration::from_secs(1));
        let res = blacklisted_listener.accept();
        match res {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
            _ => panic!("unexpected result: {:?}", res),
        }
    }

    #[test]
    fn with_blacklist_over_tcp() {
        bootstrap_with_blacklist(tcp_addr!("0.0.0.0:0"));
    }

    #[test]
    fn with_blacklist_over_utp() {
        bootstrap_with_blacklist(utp_addr!("0.0.0.0:0"));
    }

    #[test]
    fn fails_only_blacklisted_contacts() {
        let _ = env_logger::init();

        let (service0, event_rx0) = service();

        unwrap!(service0.start_listening());
        let _addr = expect_event!(event_rx0, Event::ListenerStarted(addr0) => addr0);
        let addr0 = expect_event!(event_rx0, Event::ListenerStarted(addr0) => addr0);
        let blacklisted_addr = addr0.unspecified_to_localhost();

        unwrap!(service0.set_accept_bootstrap(true));

        let config1 = unwrap!(ConfigFile::new_temporary());
        unwrap!(config1.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        unwrap!(config1.write()).hard_coded_contacts =
            vec![PeerInfo::with_rand_key(blacklisted_addr)];
        let (service1, event_rx1) = service_with_config(config1);

        unwrap!(service1.start_bootstrap(hashset!{blacklisted_addr}, CrustUser::Client));

        expect_event!(event_rx1, Event::BootstrapFailed);
    }

    #[test]
    fn fails_if_there_are_no_contacts() {
        let _ = env_logger::init();

        let (service0, event_rx0) = service();
        unwrap!(service0.start_bootstrap(HashSet::new(), CrustUser::Client));
        expect_event!(event_rx0, Event::BootstrapFailed);
    }

    #[test]
    fn fails_if_there_are_only_invalid_contacts() {
        let dead_listener = unwrap!(std::net::TcpListener::bind(addr!("0.0.0.0:0")));
        let dead_addr = unwrap!(dead_listener.local_addr());
        let dead_addr = PaAddr::Tcp(dead_addr).unspecified_to_localhost();

        let config0 = unwrap!(ConfigFile::new_temporary());
        unwrap!(config0.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        unwrap!(config0.write()).hard_coded_contacts = vec![PeerInfo::with_rand_key(dead_addr)];
        let (service0, event_rx0) = service_with_config(config0);

        unwrap!(service0.start_bootstrap(HashSet::new(), CrustUser::Client));
        expect_event!(event_rx0, Event::BootstrapFailed);
    }
}

mod when_no_message_received_within_inactivity_period {
    use super::*;

    #[test]
    fn when_heartbeats_disabled_tcp_peer_emits_lost_peer_event() {
        let (event_rx1, event_rx2, _s1, _s2) =
            bootstrap_and_do_nothing(tcp_addr!("0.0.0.0:0"), false);

        let timeout = Duration::from_millis(2 * INACTIVITY_TIMEOUT_MS);
        match event_rx1.recv_timeout(timeout) {
            Ok(Event::LostPeer(..)) => (),
            res => panic!("unexpected event: {:?}", res),
        };
        match event_rx2.recv_timeout(timeout) {
            Ok(Event::LostPeer(..)) => (),
            res => panic!("unexpected event: {:?}", res),
        };
    }

    #[test]
    fn when_heartbeats_disabled_utp_peer_emits_lost_peer_event() {
        let (event_rx1, event_rx2, _s1, _s2) =
            bootstrap_and_do_nothing(utp_addr!("0.0.0.0:0"), false);

        let timeout = Duration::from_millis(2 * INACTIVITY_TIMEOUT_MS);
        match event_rx1.recv_timeout(timeout) {
            Ok(Event::LostPeer(..)) => (),
            res => panic!("unexpected event: {:?}", res),
        };
        match event_rx2.recv_timeout(timeout) {
            Ok(Event::LostPeer(..)) => (),
            res => panic!("unexpected event: {:?}", res),
        };
    }

    #[test]
    fn when_heartbeats_exchanging_tcp_peer_stays_alive() {
        let (event_rx1, event_rx2, _s1, _s2) =
            bootstrap_and_do_nothing(tcp_addr!("0.0.0.0:0"), true);

        let timeout = Duration::from_millis(2 * INACTIVITY_TIMEOUT_MS);
        match event_rx1.recv_timeout(timeout) {
            Err(RecvTimeoutError::Timeout) => (),
            res => panic!("unexpected event: {:?}", res),
        };
        match event_rx2.recv_timeout(timeout) {
            Err(RecvTimeoutError::Timeout) => (),
            res => panic!("unexpected event: {:?}", res),
        };
    }

    #[test]
    fn when_heartbeats_exchanging_utp_peer_stays_alive() {
        let (event_rx1, event_rx2, _s1, _s2) =
            bootstrap_and_do_nothing(tcp_addr!("0.0.0.0:0"), true);

        let timeout = Duration::from_millis(2 * INACTIVITY_TIMEOUT_MS);
        match event_rx1.recv_timeout(timeout) {
            Err(RecvTimeoutError::Timeout) => (),
            res => panic!("unexpected event: {:?}", res),
        };
        match event_rx2.recv_timeout(timeout) {
            Err(RecvTimeoutError::Timeout) => (),
            res => panic!("unexpected event: {:?}", res),
        };
    }
}

#[test]
fn dropping_tcp_service_makes_remote_peer_receive_lost_peer_event() {
    let (_event_rx1, event_rx2, service1, _service2) =
        bootstrap_and_do_nothing(tcp_addr!("0.0.0.0:0"), true);
    let service2_peer_id = service1.public_id();

    drop(service1);

    expect_event!(event_rx2, Event::LostPeer(peer_id) => {
        assert_eq!(peer_id, service2_peer_id)
    });
}

#[test]
fn dropping_utp_service_makes_remote_peer_receive_lost_peer_event() {
    let (_event_rx1, event_rx2, service1, _service2) =
        bootstrap_and_do_nothing(utp_addr!("0.0.0.0:0"), true);
    let service2_peer_id = service1.public_id();

    drop(service1);

    expect_event!(event_rx2, Event::LostPeer(peer_id) => {
        assert_eq!(peer_id, service2_peer_id)
    });
}
