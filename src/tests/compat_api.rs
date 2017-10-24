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

use std;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
use rand;
use env_logger;
use compat::{self, CrustEventSender, Event};
use config::DevConfigSettings;
use priv_prelude::*;
use util::{self, UniqueId};
use ::MAX_PAYLOAD_SIZE;

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
    }
}

fn event_sender() -> (CrustEventSender<UniqueId>, Receiver<Event<UniqueId>>) {
    let (category_tx, _) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    (
        MaidSafeObserver::new(event_tx, MaidSafeEventCategory::Crust, category_tx),
        event_rx,
    )
}

fn service() -> (compat::Service<UniqueId>, Receiver<Event<UniqueId>>) {
    let (event_tx, event_rx) = event_sender();
    let config = unwrap!(ConfigFile::new_temporary());
    let uid: UniqueId = rand::random();
    let service = unwrap!(compat::Service::with_config(event_tx, config, uid));
    (service, event_rx)
}

fn exchange_messages<UID: Uid>(
    service0: &compat::Service<UID>,
    service1: &compat::Service<UID>,
    event_rx0: &Receiver<Event<UID>>,
    event_rx1: &Receiver<Event<UID>>,
    kind1: CrustUser,
) {
    let uid0 = service0.id();
    let uid1 = service1.id();

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

fn bootstrap_and_exchange<UID: Uid>(
    service0: &compat::Service<UID>,
    service1: &compat::Service<UID>,
    event_rx0: &Receiver<Event<UID>>,
    event_rx1: &Receiver<Event<UID>>,
    kind1: CrustUser,
) {
    let uid0 = service0.id();
    let uid1 = service1.id();

    unwrap!(service1.start_bootstrap(HashSet::new(), kind1));

    loop {
        expect_event!(event_rx0, Event::BootstrapAccept(id, kind) => {
            if id == uid1 && kind == kind1 {
                break;
            }
        });
    };

    expect_event!(event_rx1, Event::BootstrapConnect(id, _) => {
        assert_eq!(id, uid0);
    });

    exchange_messages(service0, service1, event_rx0, event_rx1, kind1);
}

#[test]
fn start_two_services_exchange_data() {
    let _ = env_logger::init();

    let (service0, event_rx0) = service();
    let (service1, event_rx1) = service();

    unwrap!(service0.start_listening_tcp());
    let port0 = expect_event!(event_rx0, Event::ListenerStarted(port0) => port0);

    unwrap!(service1.start_listening_tcp());
    let port1 = expect_event!(event_rx1, Event::ListenerStarted(port1) => port1);

    assert!(port0 != port1);

    const NUM_MESSAGES: usize = 100;
    const MAX_DATA_SIZE: usize = MAX_PAYLOAD_SIZE - 8;

    let uid0 = service0.id();
    let uid1 = service1.id();

    let data0 = (0..NUM_MESSAGES).map(|_| util::random_vec(MAX_DATA_SIZE)).collect::<Vec<_>>();
    let data0_compare = data0.clone();

    let data1 = (0..NUM_MESSAGES).map(|_| util::random_vec(MAX_DATA_SIZE)).collect::<Vec<_>>();
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
        unwrap!(ci_tx0.send(ci0.to_pub_connection_info()));
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
                    },
                    e => panic!("unexpected event: {:?}", e),
                }
            })
            .collect::<Vec<_>>()
        };

        assert!(data1_recv == data1_compare);
        service0
    });
    let j1 = thread::spawn(move || {
        let token = rand::random();
        service1.prepare_connection_info(token);
        let ci1 = expect_event!(event_rx1, Event::ConnectionInfoPrepared(res) => {
            assert_eq!(res.result_token, token);
            unwrap!(res.result)
        });
        unwrap!(ci_tx1.send(ci1.to_pub_connection_info()));
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
                    },
                    e => panic!("unexpected event: {:?}", e),
                }
            })
            .collect::<Vec<_>>()
        };

        assert!(data0_recv == data0_compare);
    });

    let service0 = j0.join();
    let service1 = j1.join();
    drop(service0);
    drop(service1);
}

#[test]
fn bootstrap_using_hard_coded_contacts() {
    let _ = env_logger::init();

    let (service0, event_rx0) = service();

    unwrap!(service0.start_listening_tcp());
    let port0 = expect_event!(event_rx0, Event::ListenerStarted(port0) => port0);

    unwrap!(service0.set_accept_bootstrap(true));

    let (event_tx1, event_rx1) = event_sender();
    let config1 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config1.write()).hard_coded_contacts = vec![SocketAddr::new(ip!("127.0.0.1"), port0)];
    let uid1: UniqueId = rand::random();
    let service1 = unwrap!(compat::Service::with_config(event_tx1, config1, uid1));

    bootstrap_and_exchange(&service0, &service1, &event_rx0, &event_rx1, CrustUser::Client);

    drop(service1);
    expect_event!(event_rx0, Event::LostPeer(id) => {
        assert_eq!(id, uid1);
    });
}

#[test]
fn bootstrap_using_service_discovery() {
    let _ = env_logger::init();

    let (service0, event_rx0) = service();

    unwrap!(service0.start_listening_tcp());
    let _port0 = expect_event!(event_rx0, Event::ListenerStarted(port0) => port0);

    unwrap!(service0.set_accept_bootstrap(true));
    service0.start_service_discovery();
    service0.set_service_discovery_listen(true);

    let (service1, event_rx1) = service();
    service1.start_service_discovery();
    bootstrap_and_exchange(&service0, &service1, &event_rx0, &event_rx1, CrustUser::Client);
}

#[test]
fn bootstrap_with_multiple_contact_endpoints() {
    let _ = env_logger::init();

    let (service0, event_rx0) = service();

    unwrap!(service0.start_listening_tcp());
    let port0 = expect_event!(event_rx0, Event::ListenerStarted(port0) => port0);

    unwrap!(service0.set_accept_bootstrap(true));

    let valid_address = SocketAddr::new(ip!("127.0.0.1"), port0);

    let mut addresses = Vec::new();
    let mut listeners = Vec::new();
    for _ in 0..10 {
        let listener = unwrap!(std::net::TcpListener::bind(addr!("127.0.0.1:0")));
        let addr = unwrap!(listener.local_addr());
        addresses.push(addr);
        listeners.push(listener);
    }

    addresses.push(valid_address);

    let (event_tx1, event_rx1) = event_sender();
    let config1 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config1.write()).hard_coded_contacts = addresses;
    let uid1: UniqueId = rand::random();
    let service1 = unwrap!(compat::Service::with_config(event_tx1, config1, uid1));

    bootstrap_and_exchange(&service0, &service1, &event_rx0, &event_rx1, CrustUser::Client);
}

#[test]
fn bootstrap_with_disable_external_reachability() {
    let _ = env_logger::init();

    let (event_tx0, event_rx0) = event_sender();
    let config0 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config0.write()).dev = Some(DevConfigSettings {
        disable_external_reachability_requirement: true,
    });
    let uid0: UniqueId = rand::random();
    let service0 = unwrap!(compat::Service::with_config(event_tx0, config0, uid0));

    unwrap!(service0.start_listening_tcp());
    let port0 = expect_event!(event_rx0, Event::ListenerStarted(port0) => port0);

    unwrap!(service0.set_accept_bootstrap(true));

    let (event_tx1, event_rx1) = event_sender();
    let config1 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config1.write()).hard_coded_contacts = vec![SocketAddr::new(ip!("127.0.0.1"), port0)];
    let uid1: UniqueId = rand::random();
    let service1 = unwrap!(compat::Service::with_config(event_tx1, config1, uid1));

    bootstrap_and_exchange(&service0, &service1, &event_rx0, &event_rx1, CrustUser::Node);
}

#[test]
fn bootstrap_with_blacklist() {
    let _ = env_logger::init();

    let (service0, event_rx0) = service();

    unwrap!(service0.start_listening_tcp());
    let port0 = expect_event!(event_rx0, Event::ListenerStarted(port0) => port0);

    unwrap!(service0.set_accept_bootstrap(true));

    let valid_addr = SocketAddr::new(ip!("127.0.0.1"), port0);

    let blacklisted_listener = unwrap!(std::net::TcpListener::bind(addr!("0.0.0.0:0")));
    let blacklisted_addr = unwrap!(blacklisted_listener.local_addr());
    unwrap!(blacklisted_listener.set_nonblocking(true));

    let (event_tx1, event_rx1) = event_sender();
    let config1 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config1.write()).hard_coded_contacts = vec![valid_addr, blacklisted_addr];
    let uid1: UniqueId = rand::random();
    let service1 = unwrap!(compat::Service::with_config(event_tx1, config1, uid1));

    let uid0 = service0.id();
    let uid1 = service1.id();

    unwrap!(service1.start_bootstrap(hashset!{blacklisted_addr}, CrustUser::Client));

    expect_event!(event_rx0, Event::BootstrapAccept(id, CrustUser::Client) => {
        assert_eq!(id, uid1);
    });

    expect_event!(event_rx1, Event::BootstrapConnect(id, _) => {
        assert_eq!(id, uid0);
    });

    exchange_messages(&service0, &service1, &event_rx0, &event_rx1, CrustUser::Client);

    thread::sleep(Duration::from_secs(1));
    let res = blacklisted_listener.accept();
    match res {
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
        _ => panic!("unexpected result: {:?}", res),
    }
}

#[test]
fn bootstrap_fails_only_blacklisted_contacts() {
    let _ = env_logger::init();

    let (service0, event_rx0) = service();

    unwrap!(service0.start_listening_tcp());
    let port0 = expect_event!(event_rx0, Event::ListenerStarted(port0) => port0);
    let blacklisted_addr = SocketAddr::new(ip!("127.0.0.1"), port0);

    unwrap!(service0.set_accept_bootstrap(true));

    let (event_tx1, event_rx1) = event_sender();
    let config1 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config1.write()).hard_coded_contacts = vec![blacklisted_addr];
    let uid1: UniqueId = rand::random();
    let service1 = unwrap!(compat::Service::with_config(event_tx1, config1, uid1));

    unwrap!(service1.start_bootstrap(hashset!{blacklisted_addr}, CrustUser::Client));

    expect_event!(event_rx1, Event::BootstrapFailed);
}

#[test]
fn bootstrap_fails_if_there_are_no_contacts() {
    let _ = env_logger::init();

    let (service0, event_rx0) = service();
    unwrap!(service0.start_bootstrap(HashSet::new(), CrustUser::Client));
    expect_event!(event_rx0, Event::BootstrapFailed);
}

#[test]
fn bootstrap_fails_if_there_are_only_invalid_contacts() {
    let dead_listener = unwrap!(std::net::TcpListener::bind(addr!("0.0.0.0:0")));
    let dead_addr = unwrap!(dead_listener.local_addr());

    let (event_tx0, event_rx0) = event_sender();
    let config0 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config0.write()).hard_coded_contacts = vec![dead_addr];
    let uid0: UniqueId = rand::random();
    let service0 = unwrap!(compat::Service::with_config(event_tx0, config0, uid0));

    unwrap!(service0.start_bootstrap(HashSet::new(), CrustUser::Client));
    expect_event!(event_rx0, Event::BootstrapFailed);
}

