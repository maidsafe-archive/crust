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

use config::PeerInfo;
use futures::stream;
use priv_prelude::*;
use service::Service;
use std::time::Duration;
use tokio_core::reactor::Core;
use util;

fn service_with_config(event_loop: &mut Core, config: ConfigFile) -> Service<util::UniqueId> {
    let loop_handle = event_loop.handle();
    unwrap!(event_loop.run(Service::with_config(
        &loop_handle,
        config,
        util::random_id(),
    )))
}

fn service_with_tmp_config(event_loop: &mut Core) -> Service<util::UniqueId> {
    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0"), utp_addr!("0.0.0.0:0")];
    service_with_config(event_loop, config)
}

#[test]
fn start_service() {
    let mut core = unwrap!(Core::new());
    let handle = core.handle();

    let config = unwrap!(ConfigFile::new_temporary());

    let res = core.run({
        Service::with_config(&handle, config, util::random_id()).and_then(|_service| Ok(()))
    });

    unwrap!(res);
}

#[test]
fn bootstrap_using_hard_coded_contacts() {
    let mut event_loop = unwrap!(Core::new());
    let loop_handle = event_loop.handle();

    let mut service1 = service_with_tmp_config(&mut event_loop);
    let listeners = unwrap!(event_loop.run(service1.start_listening().collect()));
    let service1_addr0 = listeners[0].addr().unspecified_to_localhost();
    let service1_addr1 = listeners[1].addr().unspecified_to_localhost();

    loop_handle.spawn(service1.bootstrap_acceptor().for_each(|_| Ok(())).then(
        |_| Ok(()),
    ));

    let config2 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config2.write()).hard_coded_contacts =
        vec![PeerInfo::new(service1_addr0, service1.public_key())];
    let mut service2 = unwrap!(event_loop.run(Service::with_config(
        &loop_handle,
        config2,
        util::random_id(),
    )));

    let service_discovery = false;
    let peer = unwrap!(event_loop.run(service2.bootstrap(
        HashSet::new(),
        service_discovery,
        CrustUser::Client,
    )));

    assert_eq!(peer.uid(), service1.id());

    let config3 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config3.write()).hard_coded_contacts =
        vec![PeerInfo::new(service1_addr1, service1.public_key())];
    let mut service3 = unwrap!(event_loop.run(Service::with_config(
        &loop_handle,
        config3,
        util::random_id(),
    )));

    let service_discovery = false;
    let peer = unwrap!(event_loop.run(service3.bootstrap(
        HashSet::new(),
        service_discovery,
        CrustUser::Client,
    )));

    assert_eq!(peer.uid(), service1.id());
}

#[test]
fn connect_works_on_localhost() {
    let mut event_loop = unwrap!(Core::new());

    let service1 = service_with_tmp_config(&mut event_loop);
    let _listener1 = unwrap!(event_loop.run(service1.start_listening().first_ok()));
    let service1_priv_conn_info = unwrap!(event_loop.run(service1.prepare_connection_info()));
    let service1_pub_conn_info = service1_priv_conn_info.to_pub_connection_info();

    let service2 = service_with_tmp_config(&mut event_loop);
    let _listener2 = unwrap!(event_loop.run(service2.start_listening().first_ok()));
    let service2_priv_conn_info = unwrap!(event_loop.run(service2.prepare_connection_info()));
    let service2_pub_conn_info = service2_priv_conn_info.to_pub_connection_info();

    let connect = service1
        .connect(service1_priv_conn_info, service2_pub_conn_info)
        .join(service2.connect(
            service2_priv_conn_info,
            service1_pub_conn_info,
        ));

    let (service1_peer, service2_peer) = unwrap!(event_loop.run(connect));
    assert_eq!(service1_peer.uid(), service2.id());
    assert_eq!(service2_peer.uid(), service1.id());
}

// None of the services in this test has listeners, therefore peer-to-peer connections are made.
#[test]
fn p2p_connections_on_localhost() {
    let mut event_loop = unwrap!(Core::new());

    let config = unwrap!(ConfigFile::new_temporary());
    let service1 = service_with_config(&mut event_loop, config);
    let service1_priv_conn_info = unwrap!(event_loop.run(service1.prepare_connection_info()));
    let service1_pub_conn_info = service1_priv_conn_info.to_pub_connection_info();

    let config = unwrap!(ConfigFile::new_temporary());
    let service2 = service_with_config(&mut event_loop, config);
    let service2_priv_conn_info = unwrap!(event_loop.run(service2.prepare_connection_info()));
    let service2_pub_conn_info = service2_priv_conn_info.to_pub_connection_info();

    let connect = service1
        .connect(service1_priv_conn_info, service2_pub_conn_info)
        .join(service2.connect(
            service2_priv_conn_info,
            service1_pub_conn_info,
        ))
        .with_timeout(Duration::from_secs(3), &event_loop.handle())
        .map(|res_opt| unwrap!(res_opt, "p2p connection timed out"));

    let (service1_peer, service2_peer) = unwrap!(event_loop.run(connect));
    assert_eq!(service1_peer.uid(), service2.id());
    assert_eq!(service2_peer.uid(), service1.id());
}

#[test]
fn peer_shutdown_closes_remote_peer_too() {
    let mut event_loop = unwrap!(Core::new());
    let loop_handle = event_loop.handle();

    let service1 = service_with_tmp_config(&mut event_loop);
    let _listener1 = unwrap!(event_loop.run(service1.start_listening().first_ok()));
    let service1_priv_conn_info = unwrap!(event_loop.run(service1.prepare_connection_info()));
    let service1_pub_conn_info = service1_priv_conn_info.to_pub_connection_info();

    let service2 = service_with_tmp_config(&mut event_loop);
    let _listener2 = unwrap!(event_loop.run(service2.start_listening().first_ok()));
    let service2_priv_conn_info = unwrap!(event_loop.run(service2.prepare_connection_info()));
    let service2_pub_conn_info = service2_priv_conn_info.to_pub_connection_info();

    let connect = service1
        .connect(service1_priv_conn_info, service2_pub_conn_info)
        .join(service2.connect(
            service2_priv_conn_info,
            service1_pub_conn_info,
        ));
    let (service1_peer, service2_peer) = unwrap!(event_loop.run(connect));

    drop(service1_peer);

    unwrap!(
        event_loop.run(
            service2_peer
                .for_each(|_| Ok(()))
                .map_err(|e| panic!("peer error: {}", e))
                .with_timeout(Duration::from_secs(10), &loop_handle)
                .and_then(|res| res.ok_or_else(|| panic!("timed out"))),
        )
    );
}

#[test]
fn exchange_data_between_two_peers() {
    let mut event_loop = unwrap!(Core::new());
    let loop_handle = event_loop.handle();

    let service1 = service_with_tmp_config(&mut event_loop);
    let _listener1 = unwrap!(event_loop.run(service1.start_listening().first_ok()));
    let service1_priv_conn_info = unwrap!(event_loop.run(service1.prepare_connection_info()));
    let service1_pub_conn_info = service1_priv_conn_info.to_pub_connection_info();

    let service2 = service_with_tmp_config(&mut event_loop);
    let _listener2 = unwrap!(event_loop.run(service2.start_listening().first_ok()));
    let service2_priv_conn_info = unwrap!(event_loop.run(service2.prepare_connection_info()));
    let service2_pub_conn_info = service2_priv_conn_info.to_pub_connection_info();

    let connect = service1
        .connect(service1_priv_conn_info, service2_pub_conn_info)
        .join(service2.connect(
            service2_priv_conn_info,
            service1_pub_conn_info,
        ));
    let (service1_peer, service2_peer) = unwrap!(event_loop.run(connect));

    const NUM_MESSAGES: u64 = 100;
    let random_data = || {
        const MAX_DATA_SIZE: usize = 512;
        (0..NUM_MESSAGES)
            .map(|_| util::random_vec(MAX_DATA_SIZE))
            .collect::<Vec<_>>()
    };

    let data1 = random_data();
    let data2 = random_data();

    let spawn_sending = |data, peer: Peer<util::UniqueId>| {
        let (peer_sink, peer_stream) = peer.split();
        let data_stream = stream::iter_ok::<_, ()>(data)
            .map_err(|_| PeerError::Destroyed) // makes compiler happy regarding error type
            .map(|item| (1, item));
        let send_all = peer_sink.send_all(data_stream).then(|_| Ok(()));
        loop_handle.spawn(send_all);
        peer_stream
    };

    let peer1_stream = spawn_sending(data1.clone(), service1_peer);
    let peer2_stream = spawn_sending(data2.clone(), service2_peer);

    let received_data = unwrap!(event_loop.run(peer1_stream.take(NUM_MESSAGES).collect()));
    assert_eq!(received_data, data2);

    let received_data = unwrap!(event_loop.run(peer2_stream.take(NUM_MESSAGES).collect()));
    assert_eq!(received_data, data1);
}

/*

    Things to test:

    can we bootstrap?
    are bootstrap blacklists respected?
    are external reachability requirements respected?
    are whitelists respected?

    can we connect?
    even with no listeners? - not really testable over loopback

*/
