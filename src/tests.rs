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

use maidsafe_utilities::event_sender::{MaidSafeObserver, MaidSafeEventCategory};
use maidsafe_utilities::log;
use std::sync::mpsc::{self, Receiver};

use config_handler::Config;
use event::Event;
use service::Service;
use socket_addr::SocketAddr;
use static_contact_info::StaticContactInfo;

fn get_event_sender()
    -> (::CrustEventSender, Receiver<Event>)
{
    let (category_tx, _) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    (MaidSafeObserver::new(event_tx, MaidSafeEventCategory::Crust, category_tx), event_rx)
}

fn localhost(port: u16) -> SocketAddr {
    use std::net::IpAddr;
    use std::net::SocketAddr as StdSocketAddr;
    use std::str::FromStr;

    SocketAddr(StdSocketAddr::new(unwrap_result!(IpAddr::from_str("127.0.0.1")), port))
}

fn localhost_contact_info(port: u16) -> StaticContactInfo {
    StaticContactInfo {
        tcp_acceptors: vec![localhost(port)],
        tcp_mapper_servers: vec![],
    }
}

#[test]
fn bootstrap_two_services_and_exchange_messages() {
    let _ = log::init(true);

    let config0 = Config::default();
    let (event_tx0, event_rx0) = get_event_sender();
    let mut service0 = unwrap_result!(Service::with_config(event_tx0, config0));

    let _ = unwrap_result!(service0.start_listening_tcp());

    let port0 = match unwrap_result!(event_rx0.recv()) {
        Event::ListenerStarted(port) => port,
        e => panic!("unexpected event {:?}", e),
    };

    let mut config1 = Config::default();
    config1.hard_coded_contacts = vec![localhost_contact_info(port0)];

    let (event_tx1, event_rx1) = get_event_sender();
    let mut service1 = unwrap_result!(Service::with_config(event_tx1, config1));

    let _ = unwrap_result!(service1.start_bootstrap());

    let peer_id0 = match unwrap_result!(event_rx1.recv()) {
        Event::BootstrapConnect(peer_id) => {
            assert_eq!(peer_id, service0.id());
            peer_id
        }
        e => panic!("unexpected event {:?}", e),
    };

    let peer_id1 = match unwrap_result!(event_rx0.recv()) {
        Event::BootstrapAccept(peer_id) => {
            assert_eq!(peer_id, service1.id());
            peer_id
        }
        e => panic!("unexpected event {:?}", e),
    };

    let message0 = "hello from 0".as_bytes().to_owned();
    unwrap_result!(service0.send(peer_id1, message0.clone()));

    match unwrap_result!(event_rx1.recv()) {
        Event::NewMessage(peer_id, data) => {
            assert_eq!(peer_id, peer_id0);
            assert_eq!(data, message0);
        }
        e => panic!("unexpected event {:?}", e),
    }

    let message1 = "hello from 1".as_bytes().to_owned();
    unwrap_result!(service1.send(peer_id0, message1.clone()));

    match unwrap_result!(event_rx0.recv()) {
        Event::NewMessage(peer_id, data) => {
            assert_eq!(peer_id, peer_id1);
            assert_eq!(data, message1);
        }
        e => panic!("unexpected event {:?}", e),
    }
}
