// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::*;
use config::PeerInfo;
use env_logger;
use future_utils::StreamExt;
use futures::sync::mpsc;
use futures::{future, stream, Future, Stream};
use net::service_discovery::server::Server;
use priv_prelude::*;
use std::time::Duration;
use tokio_core::reactor::Core;

#[test]
fn multiple_server_instances_in_parallel() {
    let num_servers = 3;
    let num_discovers = 3;
    let starting_port = 45_666;

    let mut core = unwrap!(Core::new());
    let handle = core.handle();

    let res = core.run(future::lazy(move || {
        let mut servers = Vec::new();
        for i in 0..num_servers {
            let server = Server::new(&handle, starting_port + i, i);
            servers.push(server);
        }

        let mut futures = Vec::new();
        for i in 0..num_servers {
            for j in 0..num_discovers {
                let (our_pk, our_sk) = gen_encrypt_keypair();
                let discover = discover::<u16>(&handle, starting_port + i, our_sk, our_pk)
                    .map_err(|e| panic!("error discovering: {}", e))
                    .flatten_stream()
                    .with_timeout(Duration::from_secs(2), &handle)
                    .collect()
                    .and_then(move |responses| {
                        trace!(
                            "trying discoverer {} of {} for server {}, got {:?}",
                            j,
                            num_discovers,
                            i,
                            responses
                        );

                        assert!(!responses.is_empty());
                        for (_, msg) in responses {
                            assert_eq!(msg, i);
                        }
                        Ok(())
                    });
                futures.push(discover);
            }
        }

        stream::futures_unordered(futures)
            .for_each(|()| Ok(()))
            .and_then(|()| Ok(servers))
    }));
    let _servers = unwrap!(res);
}

fn peer_addrs(peers: &HashSet<PeerInfo>) -> HashSet<PaAddr> {
    peers.iter().map(|peer| peer.addr).collect()
}

#[test]
fn service_discovery() {
    let _logger = env_logger::init();

    let mut core = unwrap!(Core::new());
    let handle = core.handle();

    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).service_discovery_port = Some(0);
    let (tx, rx) = mpsc::unbounded();

    let (our_pk, _) = gen_encrypt_keypair();
    let sd = unwrap!(ServiceDiscovery::new(
        &handle,
        &config,
        &hashset!{},
        rx,
        our_pk,
    ));
    let port = sd.port();

    let f = {
        let (our_pk, our_sk) = gen_encrypt_keypair();
        discover::<HashSet<PeerInfo>>(&handle, port, our_sk.clone(), our_pk)
            .map_err(|e| panic!("discover error: {}", e))
            .flatten_stream()
            .with_timeout(Duration::from_secs(2), &handle)
            .collect()
            .and_then(move |v| {
                assert!(v.into_iter().any(|(_, addrs)| addrs == hashset!{}));

                let some_addrs = hashset!{
                    tcp_addr!("1.2.3.4:555"),
                    tcp_addr!("5.4.3.2:111"),
                };
                unwrap!(tx.unbounded_send(some_addrs.clone()));

                let handle0 = handle.clone();

                Timeout::new(Duration::from_millis(100), &handle)
                    .map_err(|e| panic!(e))
                    .and_then(move |()| {
                        discover::<HashSet<PeerInfo>>(&handle0, port, our_sk, our_pk)
                            .map_err(|e| panic!("discover error: {}", e))
                    }).flatten_stream()
                    .until({
                        Timeout::new(Duration::from_millis(200), &handle).map_err(|e| panic!(e))
                    }).collect()
                    .map(move |v| {
                        assert!(
                            v.into_iter()
                                .any(|(_, peers)| peer_addrs(&peers) == some_addrs)
                        );
                        drop(sd);
                    })
            })
    };
    let res = core.run(f);
    unwrap!(res)
}
