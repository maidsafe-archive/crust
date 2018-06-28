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
use env_logger;
use future_utils;
use future_utils::bi_channel;
use futures::sync::oneshot;
use netsim::device::ipv4::Ipv4NatBuilder;
use netsim::node::Ipv4Node;
use netsim::{self, Ipv4Range, Network};
use priv_prelude::*;
use tokio_core::reactor::Core;
use {util, Service};

#[test]
fn tcp_bootstrap_over_poor_connection() {
    let _ = env_logger::init();

    let mut core = unwrap!(Core::new());
    let handle = core.handle();
    let network = Network::new(&handle);
    let network_handle = network.handle();

    let res = core.run(future::lazy(|| {
        let (addr_tx, addr_rx) = oneshot::channel();

        let server_node = netsim::node::ipv4::machine(|ip| {
            let mut core = unwrap!(Core::new());
            let handle = core.handle();

            let res = core.run(future::lazy(|| {
                let config = unwrap!(ConfigFile::new_temporary());
                let addr = SocketAddr::V4(SocketAddrV4::new(ip, 1234));
                unwrap!(config.write()).listen_addresses = vec![PaAddr::Tcp(addr)];
                Service::with_config(&handle, config, util::random_id())
                    .map_err(|e| panic!("error creating service: {}", e))
                    .and_then(move |mut service| {
                        let server_info = PeerInfo {
                            addr: PaAddr::Tcp(SocketAddr::V4(SocketAddrV4::new(ip, 1234))),
                            pub_key: service.public_key(),
                        };

                        unwrap!(addr_tx.send(server_info));

                        let listening = {
                            service
                                .start_listening()
                                .map_err(|e| panic!("error starting listeners: {}", e))
                                .collect()
                        };

                        service
                            .bootstrap_acceptor()
                            .into_future()
                            .map_err(|(e, _)| panic!("error receiving bootstrap peer: {}", e))
                            .and_then(|(stream_opt, _bootstrap_acceptor)| {
                                let stream = unwrap!(stream_opt);
                                stream
                                    .into_future()
                                    .map_err(|(e, _)| panic!("error reading from stream: {}", e))
                                    .and_then(|(msg_opt, stream)| {
                                        let msg = unwrap!(msg_opt);
                                        stream
                                            .send((0, msg))
                                            .map_err(|e| panic!("error sending on stream: {}", e))
                                            .and_then(move |_stream| {
                                                // TODO: find a better way to gracefully close a Service.
                                                Timeout::new(Duration::from_secs(1), &handle).map(
                                                    |()| {
                                                        drop(service);
                                                    },
                                                )
                                            })
                                    })
                            })
                            .while_driving(listening)
                            .map_err(|(e, _)| e)
                            .map(|((), _listening)| ())
                    })
            }));
            res.void_unwrap()
        });

        let client_node = netsim::node::ipv4::machine(|_ip| {
            let mut core = unwrap!(Core::new());
            let handle = core.handle();

            let res = core.run(future::lazy(move || {
                addr_rx
                    .map_err(|_e| panic!("addr never got sent"))
                    .and_then(move |server_info| {
                        let config = unwrap!(ConfigFile::new_temporary());
                        unwrap!(config.write()).hard_coded_contacts = vec![server_info];
                        Service::with_config(&handle, config, util::random_id())
                            .map_err(|e| panic!("error starting service: {}", e))
                            .and_then(move |mut service| {
                                service
                                    .bootstrap(HashSet::new(), false, CrustUser::Client)
                                    .map_err(|e| panic!("bootstrap error: {}", e))
                                    .and_then(|stream| {
                                        let send_data = util::random_vec(1024);

                                        stream
                                            .send((0, send_data.clone()))
                                            .map_err(|e| panic!("error writing to stream: {}", e))
                                            .and_then(move |stream| {
                                                stream
                                                    .into_future()
                                                    .map_err(|(e, _)| {
                                                        panic!("error reading from stream: {}", e)
                                                    })
                                                    .map(move |(recv_data_opt, _stream)| {
                                                        let recv_data = unwrap!(recv_data_opt);
                                                        assert_eq!(recv_data, send_data);
                                                        drop(service);
                                                    })
                                            })
                                    })
                            })
                    })
            }));
            res.void_unwrap()
        });

        let client_node = {
            netsim::node::ipv4::nat(Ipv4NatBuilder::default(), client_node)
                .latency(Duration::from_millis(300), Duration::from_millis(30))
                .hops(5)
                .packet_loss(0.1, Duration::from_millis(30))
        };

        let (spawn_complete, _plug) = netsim::spawn::ipv4_tree(
            &network_handle,
            Ipv4Range::global(),
            netsim::node::ipv4::router((server_node, client_node)),
        );

        spawn_complete.resume_unwind().map(|((), ())| ())
    }));
    res.void_unwrap()
}

#[test]
fn rendezvous_connect_over_poor_connection() {
    let _ = env_logger::init();

    let mut core = unwrap!(Core::new());
    let handle = core.handle();
    let network = Network::new(&handle);
    let network_handle = network.handle();

    let send_data_a = util::random_vec(1024);
    let send_data_a_clone = send_data_a.clone();
    let send_data_b = util::random_vec(1024);
    let send_data_b_clone = send_data_b.clone();

    let (drop_tx_a0, drop_rx_a0) = future_utils::drop_notify();
    let (drop_tx_b0, drop_rx_b0) = future_utils::drop_notify();
    let (addr_tx_a0, addr_rx_a0) = oneshot::channel();
    let (addr_tx_b0, addr_rx_b0) = oneshot::channel();
    let (drop_tx_a1, drop_rx_a1) = future_utils::drop_notify();
    let (drop_tx_b1, drop_rx_b1) = future_utils::drop_notify();
    let (addr_tx_a1, addr_rx_a1) = oneshot::channel();
    let (addr_tx_b1, addr_rx_b1) = oneshot::channel();
    let (drop_tx_ac, drop_rx_ac) = future_utils::drop_notify();
    let (drop_tx_bc, drop_rx_bc) = future_utils::drop_notify();
    let (ci_channel1, ci_channel2) = bi_channel::unbounded();
    let res = core.run(future::lazy(|| {
        let rendezvous_server_node_0 = netsim::node::ipv4::machine(|ip| {
            let mut core = unwrap!(Core::new());
            let handle = core.handle();

            let res = core.run(future::lazy(|| {
                let config = unwrap!(ConfigFile::new_temporary());
                let addr = SocketAddr::V4(SocketAddrV4::new(ip, 1234));
                unwrap!(config.write()).listen_addresses = vec![PaAddr::Utp(addr)];
                Service::with_config(&handle, config, util::random_id())
                    .map_err(|e| panic!("error creating service: {}", e))
                    .and_then(move |service| {
                        let server_info = PeerInfo {
                            addr: PaAddr::Utp(SocketAddr::V4(SocketAddrV4::new(ip, 1234))),
                            pub_key: service.public_key(),
                        };

                        unwrap!(addr_tx_a0.send(server_info.clone()));
                        unwrap!(addr_tx_b0.send(server_info));

                        let listening = {
                            service
                                .start_listening()
                                .map_err(|e| panic!("error starting listeners: {}", e))
                                .collect()
                        };

                        drop_rx_a0
                            .and_then(|()| {
                                drop_rx_b0.map(|()| {
                                    drop(service);
                                })
                            })
                            .while_driving(listening)
                            .map_err(|(e, _)| e)
                            .map(|((), _listening)| ())
                    })
            }));
            res.void_unwrap()
        });

        let rendezvous_server_node_1 = netsim::node::ipv4::machine(|ip| {
            let mut core = unwrap!(Core::new());
            let handle = core.handle();

            let res = core.run(future::lazy(|| {
                let config = unwrap!(ConfigFile::new_temporary());
                let addr = SocketAddr::V4(SocketAddrV4::new(ip, 1234));
                unwrap!(config.write()).listen_addresses = vec![PaAddr::Utp(addr)];
                Service::with_config(&handle, config, util::random_id())
                    .map_err(|e| panic!("error creating service: {}", e))
                    .and_then(move |service| {
                        let server_info = PeerInfo {
                            addr: PaAddr::Utp(SocketAddr::V4(SocketAddrV4::new(ip, 1234))),
                            pub_key: service.public_key(),
                        };

                        unwrap!(addr_tx_a1.send(server_info.clone()));
                        unwrap!(addr_tx_b1.send(server_info));

                        let listening = {
                            service
                                .start_listening()
                                .map_err(|e| panic!("error starting listeners: {}", e))
                                .collect()
                        };

                        drop_rx_a1
                            .and_then(|()| {
                                drop_rx_b1.map(|()| {
                                    drop(service);
                                })
                            })
                            .while_driving(listening)
                            .map_err(|(e, _)| e)
                            .map(|((), _listening)| ())
                    })
            }));
            res.void_unwrap()
        });

        let node_a = netsim::node::ipv4::machine(|_ip| {
            let mut core = unwrap!(Core::new());
            let handle = core.handle();

            let res = core.run(future::lazy(|| {
                addr_rx_a0
                    .map_err(|_e| panic!("never received rendezvous server info"))
                    .and_then(|server_info_0| {
                        addr_rx_a1
                            .map_err(|_e| panic!("never received rendezvous server info"))
                            .map(|server_info_1| vec![server_info_0, server_info_1])
                    })
                    .and_then(|server_infos| {
                        let config = unwrap!(ConfigFile::new_temporary());
                        unwrap!(config.write()).hard_coded_contacts = server_infos;
                        Service::with_config(&handle, config, util::random_id())
                            .map_err(|e| panic!("error creating service: {}", e))
                            .and_then(move |service| {
                                service
                                    .connect(ci_channel1)
                                    .map_err(|e| panic!("connect error: {}", e))
                                    .and_then(move |stream| {
                                        stream
                                            .send((0, send_data_a_clone))
                                            .map_err(|e| panic!("send error: {}", e))
                                            .and_then(move |stream| {
                                                trace!("node_a connected!");
                                                stream
                                                    .into_future()
                                                    .map_err(|(e, _)| {
                                                        panic!("receive error: {}", e)
                                                    })
                                                    .and_then(move |(recv_data_b, stream)| {
                                                        drop(drop_tx_a0);
                                                        drop(drop_tx_a1);
                                                        drop(drop_tx_ac);

                                                        drop_rx_bc.map(move |()| {
                                                            drop(stream);
                                                            drop(service);
                                                            unwrap!(recv_data_b)
                                                        })
                                                    })
                                            })
                                    })
                            })
                    })
            }));
            res.void_unwrap()
        });

        let node_b = netsim::node::ipv4::machine(|_ip| {
            let mut core = unwrap!(Core::new());
            let handle = core.handle();

            let res = core.run(future::lazy(|| {
                addr_rx_b0
                    .map_err(|_e| panic!("never received rendezvous server info"))
                    .and_then(|server_info_0| {
                        addr_rx_b1
                            .map_err(|_e| panic!("never received rendezvous server info"))
                            .map(|server_info_1| vec![server_info_0, server_info_1])
                    })
                    .and_then(|server_infos| {
                        let config = unwrap!(ConfigFile::new_temporary());
                        unwrap!(config.write()).hard_coded_contacts = server_infos;
                        Service::with_config(&handle, config, util::random_id())
                            .map_err(|e| panic!("error creating service: {}", e))
                            .and_then(move |service| {
                                service
                                    .connect(ci_channel2)
                                    .map_err(|e| panic!("connect error: {}", e))
                                    .and_then(move |stream| {
                                        stream
                                            .send((0, send_data_b_clone))
                                            .map_err(|e| panic!("send error: {}", e))
                                            .and_then(move |stream| {
                                                trace!("node_b connected!");
                                                stream
                                                    .into_future()
                                                    .map_err(|(e, _)| {
                                                        panic!("receive error: {}", e)
                                                    })
                                                    .and_then(move |(recv_data_a, stream)| {
                                                        drop(drop_tx_b0);
                                                        drop(drop_tx_b1);
                                                        drop(drop_tx_bc);

                                                        drop_rx_ac.map(move |()| {
                                                            drop(stream);
                                                            drop(service);
                                                            unwrap!(recv_data_a)
                                                        })
                                                    })
                                            })
                                    })
                            })
                    })
            }));
            res.void_unwrap()
        });

        let node_a = {
            let nat = Ipv4NatBuilder::default().blacklist_unrecognized_addrs();
            netsim::node::ipv4::nat(nat, node_a)
                .latency(Duration::from_millis(200), Duration::from_millis(20))
                .hops(3)
                .packet_loss(0.1, Duration::from_millis(20))
        };

        let node_b = {
            let nat = Ipv4NatBuilder::default().blacklist_unrecognized_addrs();
            netsim::node::ipv4::nat(nat, node_b)
                .latency(Duration::from_millis(200), Duration::from_millis(20))
                .hops(3)
                .packet_loss(0.1, Duration::from_millis(20))
        };

        let router = netsim::node::ipv4::router((
            rendezvous_server_node_0,
            rendezvous_server_node_1,
            node_a,
            node_b,
        ));
        let (spawn_complete, _plug) =
            netsim::spawn::ipv4_tree(&network_handle, Ipv4Range::global(), router);

        spawn_complete
            .resume_unwind()
            .map(|((), (), recv_data_b, recv_data_a)| {
                assert_eq!(send_data_a, recv_data_a);
                assert_eq!(send_data_b, recv_data_b);
            })
    }));
    res.void_unwrap()
}
