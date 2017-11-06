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

use priv_prelude::*;
use service::Service;
use tokio_core::reactor::Core;
use util;

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

    let config1 = unwrap!(ConfigFile::new_temporary());
    let mut service1 = unwrap!(event_loop.run(Service::with_config(
        &loop_handle,
        config1,
        util::random_id(),
    )));
    let listener = unwrap!(event_loop.run(service1.start_listener()));
    let service1_port = listener.addr().port();

    loop_handle.spawn(service1.bootstrap_acceptor().for_each(|_| Ok(())).then(
        |_| Ok(()),
    ));

    let config2 = unwrap!(ConfigFile::new_temporary());
    unwrap!(config2.write()).hard_coded_contacts =
        vec![SocketAddr::new(ip!("127.0.0.1"), service1_port)];
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
}

#[test]
fn connect_works_on_localhost() {
    let mut event_loop = unwrap!(Core::new());
    let loop_handle = event_loop.handle();

    let config1 = unwrap!(ConfigFile::new_temporary());
    let service1 = unwrap!(event_loop.run(Service::with_config(
        &loop_handle,
        config1,
        util::random_id(),
    )));
    unwrap!(event_loop.run(service1.start_listener()));
    let service1_priv_conn_info = unwrap!(event_loop.run(service1.prepare_connection_info()));
    let service1_pub_conn_info = service1_priv_conn_info.to_pub_connection_info();

    let config2 = unwrap!(ConfigFile::new_temporary());
    let service2 = unwrap!(event_loop.run(Service::with_config(
        &loop_handle,
        config2,
        util::random_id(),
    )));
    unwrap!(event_loop.run(service2.start_listener()));
    let service2_priv_conn_info = unwrap!(event_loop.run(service2.prepare_connection_info()));
    let service2_pub_conn_info = service2_priv_conn_info.to_pub_connection_info();

    let connect = service1
        .connect(service1_priv_conn_info, service2_pub_conn_info)
        .join(service2.connect(
            service2_priv_conn_info,
            service1_pub_conn_info,
        ))
        .and_then(|peers| Ok(peers));

    let (service1_peer, service2_peer) = unwrap!(event_loop.run(connect));
    assert_eq!(service1_peer.uid(), service2.id());
    assert_eq!(service2_peer.uid(), service1.id());
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
