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

fn bootstrap_over_poor_connection<F>(make_addr: F)
where
    F: 'static + FnOnce(Ipv4Addr, u16) -> PaAddr + Send + Clone,
{
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
                let addr = make_addr(ip, 1234);
                unwrap!(config.write()).listen_addresses = vec![addr];
                let (our_pk, our_sk) = gen_encrypt_keypair();
                Service::with_config(&handle, config, our_sk, our_pk)
                    .map_err(|e| panic!("error creating service: {}", e))
                    .and_then(move |mut service| {
                        let server_info = PeerInfo {
                            addr,
                            pub_key: service.public_id(),
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
                            .and_then(|(peer_opt, _bootstrap_acceptor)| {
                                let peer = unwrap!(peer_opt);
                                peer.into_future()
                                    .map_err(|(e, _)| panic!("error reading from peer: {}", e))
                                    .and_then(|(msg_opt, peer)| {
                                        let msg = unwrap!(msg_opt);
                                        peer.send(msg.freeze())
                                            .map_err(|e| panic!("error sending to peer: {}", e))
                                            .and_then(move |_peer| {
                                                // TODO: find a better way to gracefully close a Service.
                                                Timeout::new(Duration::from_secs(1), &handle).map(
                                                    |()| {
                                                        drop(service);
                                                    },
                                                )
                                            })
                                    })
                            }).while_driving(listening)
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
                        unwrap!(config.write()).bootstrap_cache_name =
                            Some(util::bootstrap_cache_tmp_file());
                        unwrap!(config.write()).hard_coded_contacts = vec![server_info];
                        let (our_pk, our_sk) = gen_encrypt_keypair();
                        Service::with_config(&handle, config, our_sk, our_pk)
                            .map_err(|e| panic!("error starting service: {}", e))
                            .and_then(move |mut service| {
                                service
                                    .bootstrap(HashSet::new(), false, CrustUser::Client)
                                    .map_err(|e| panic!("bootstrap error: {}", e))
                                    .and_then(|peer| {
                                        let send_data = util::random_vec(1024);

                                        peer.send(Bytes::from(send_data.clone()))
                                            .map_err(|e| panic!("error writing to peer: {}", e))
                                            .and_then(move |peer| {
                                                peer.into_future()
                                                    .map_err(|(e, _)| {
                                                        panic!("error reading from peer: {}", e)
                                                    }).map(move |(recv_data_opt, _peer)| {
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
fn tcp_bootstrap_over_poor_connection() {
    bootstrap_over_poor_connection(|ip, port| {
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        PaAddr::Tcp(addr)
    });
}

fn rendezvous_connect_over_poor_connection<F>(make_addr1: F)
where
    F: 'static + FnOnce(Ipv4Addr, u16) -> PaAddr + Send + Clone,
{
    let _ = env_logger::init();

    let mut core = unwrap!(Core::new());
    let handle = core.handle();
    let network = Network::new(&handle);
    let network_handle = network.handle();

    let send_data_a = util::random_vec(1024);
    let send_data_a_clone = send_data_a.clone();
    let send_data_b = util::random_vec(1024);
    let send_data_b_clone = send_data_b.clone();

    let make_addr2 = make_addr1.clone();

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
                let addr = make_addr1(ip, 1234);
                unwrap!(config.write()).listen_addresses = vec![addr];
                let (our_pk, our_sk) = gen_encrypt_keypair();
                Service::with_config(&handle, config, our_sk, our_pk)
                    .map_err(|e| panic!("error creating service: {}", e))
                    .and_then(move |service| {
                        let server_info = PeerInfo {
                            addr,
                            pub_key: service.public_id(),
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
                            }).while_driving(listening)
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
                let addr = make_addr2(ip, 1234);
                unwrap!(config.write()).listen_addresses = vec![addr];
                let (our_pk, our_sk) = gen_encrypt_keypair();
                Service::with_config(&handle, config, our_sk, our_pk)
                    .map_err(|e| panic!("error creating service: {}", e))
                    .and_then(move |service| {
                        let server_info = PeerInfo {
                            addr,
                            pub_key: service.public_id(),
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
                            }).while_driving(listening)
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
                    }).and_then(|server_infos| {
                        let config = unwrap!(ConfigFile::new_temporary());
                        unwrap!(config.write()).hard_coded_contacts = server_infos;
                        let (our_pk, our_sk) = gen_encrypt_keypair();
                        Service::with_config(&handle, config, our_sk, our_pk)
                            .map_err(|e| panic!("error creating service: {}", e))
                            .and_then(move |service| {
                                service
                                    .connect(ci_channel1)
                                    .map_err(|e| panic!("connect error: {}", e))
                                    .and_then(move |peer| {
                                        peer.send(Bytes::from(send_data_a_clone))
                                            .map_err(|e| panic!("send error: {}", e))
                                            .and_then(move |peer| {
                                                trace!("node_a connected!");
                                                peer.into_future()
                                                    .map_err(|(e, _)| {
                                                        panic!("receive error: {}", e)
                                                    }).and_then(move |(recv_data_b, peer)| {
                                                        drop(drop_tx_a0);
                                                        drop(drop_tx_a1);
                                                        drop(drop_tx_ac);

                                                        drop_rx_bc.map(move |()| {
                                                            drop(peer);
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
                    }).and_then(|server_infos| {
                        let config = unwrap!(ConfigFile::new_temporary());
                        unwrap!(config.write()).hard_coded_contacts = server_infos;
                        let (our_pk, our_sk) = gen_encrypt_keypair();
                        Service::with_config(&handle, config, our_sk, our_pk)
                            .map_err(|e| panic!("error creating service: {}", e))
                            .and_then(move |service| {
                                service
                                    .connect(ci_channel2)
                                    .map_err(|e| panic!("connect error: {}", e))
                                    .and_then(move |peer| {
                                        peer.send(Bytes::from(send_data_b_clone))
                                            .map_err(|e| panic!("send error: {}", e))
                                            .and_then(move |peer| {
                                                trace!("node_b connected!");
                                                peer.into_future()
                                                    .map_err(|(e, _)| {
                                                        panic!("receive error: {}", e)
                                                    }).and_then(move |(recv_data_a, peer)| {
                                                        drop(drop_tx_b0);
                                                        drop(drop_tx_b1);
                                                        drop(drop_tx_bc);

                                                        drop_rx_ac.map(move |()| {
                                                            drop(peer);
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

#[test]
fn tcp_rendezvous_connect_over_poor_connection() {
    rendezvous_connect_over_poor_connection(|ip, port| {
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        PaAddr::Tcp(addr)
    });
}

#[test]
fn utp_rendezvous_connect_over_poor_connection() {
    rendezvous_connect_over_poor_connection(|ip, port| {
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        PaAddr::Utp(addr)
    });
}

mod probe_nat {
    use super::*;
    use future_utils::DropNotice;
    use p2p::NatType;

    fn utp_addr(ip: Ipv4Addr, port: u16) -> PaAddr {
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        PaAddr::Utp(addr)
    }

    #[allow(unused_qualifications)]
    fn make_stun_server(
        server_info_tx: oneshot::Sender<PeerInfo>,
        client_drop_rx: DropNotice,
    ) -> impl netsim::node::Ipv4Node {
        netsim::node::ipv4::machine(move |ip| {
            let mut evloop = unwrap!(Core::new());

            let config = unwrap!(ConfigFile::new_temporary());
            let addr = utp_addr(ip, 1234);
            unwrap!(config.write()).listen_addresses = vec![addr];
            let (our_pk, our_sk) = gen_encrypt_keypair();

            let run_service = Service::with_config(&evloop.handle(), config, our_sk, our_pk)
                .map_err(|e| panic!("error creating service: {}", e))
                .and_then(move |service| {
                    let server_info = PeerInfo {
                        addr,
                        pub_key: service.public_id(),
                    };
                    unwrap!(server_info_tx.send(server_info));

                    let listeners = service
                        .start_listening()
                        .map_err(|e| panic!("error starting listeners: {}", e))
                        .collect();

                    client_drop_rx
                        .map(|()| drop(service))
                        .while_driving(listeners)
                        .map_err(|(e, _)| e)
                        .map(|((), _listeners)| ())
                });
            unwrap!(evloop.run(run_service));
        })
    }

    #[test]
    fn it_returns_unknown_type_when_only_1_rendezvous_server_is_given() {
        let mut evloop = unwrap!(Core::new());
        let handle = evloop.handle();
        let network = Network::new(&handle);

        let (client_drop_tx, client_drop_rx) = future_utils::drop_notify();
        let (server_info_tx, server_info_rx) = oneshot::channel();

        let rendezvous_server1 = make_stun_server(server_info_tx, client_drop_rx);
        let client = netsim::node::ipv4::machine(|_ip| {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();

            let task = server_info_rx
                .map_err(|e| panic!(e))
                .and_then(|server_info| {
                    let config = unwrap!(ConfigFile::new_temporary());
                    unwrap!(config.write()).hard_coded_contacts = vec![server_info];
                    let (our_pk, our_sk) = gen_encrypt_keypair();

                    Service::with_config(&handle, config, our_sk, our_pk)
                        .and_then(|service| service.probe_nat())
                        .and_then(|nat_type| {
                            assert_eq!(nat_type, NatType::Unknown);
                            drop(client_drop_tx);
                            Ok(())
                        })
                });
            unwrap!(evloop.run(task));
        });
        let client = netsim::node::ipv4::nat(Ipv4NatBuilder::default(), client);

        let router = netsim::node::ipv4::router((rendezvous_server1, client));
        let (spawn_complete, _ipv4_plug) =
            netsim::spawn::ipv4_tree(&network.handle(), Ipv4Range::global(), router);

        let _ = unwrap!(evloop.run(spawn_complete));
    }

    #[test]
    fn it_properly_detects_endpoint_independent_mapping() {
        let mut evloop = unwrap!(Core::new());
        let handle = evloop.handle();
        let network = Network::new(&handle);

        let (client_drop_tx1, client_drop_rx1) = future_utils::drop_notify();
        let (client_drop_tx2, client_drop_rx2) = future_utils::drop_notify();
        let (server1_info_tx, server1_info_rx) = oneshot::channel();
        let (server2_info_tx, server2_info_rx) = oneshot::channel();

        let rendezvous_server1 = make_stun_server(server1_info_tx, client_drop_rx1);
        let rendezvous_server2 = make_stun_server(server2_info_tx, client_drop_rx2);

        let client = netsim::node::ipv4::machine(|_ip| {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();

            let task = server1_info_rx
                .map_err(|e| panic!(e))
                .and_then(|server1_info| {
                    server2_info_rx
                        .map_err(|e| panic!(e))
                        .map(move |server2_info| (server1_info, server2_info))
                }).and_then(|(server1_info, server2_info)| {
                    let config = unwrap!(ConfigFile::new_temporary());
                    unwrap!(config.write()).hard_coded_contacts = vec![server1_info, server2_info];
                    let (our_pk, our_sk) = gen_encrypt_keypair();

                    Service::with_config(&handle, config, our_sk, our_pk)
                        .and_then(|service| service.probe_nat())
                        .and_then(|nat_type| {
                            assert_eq!(nat_type, NatType::EIM);
                            drop(client_drop_tx1);
                            drop(client_drop_tx2);
                            Ok(())
                        })
                });
            unwrap!(evloop.run(task));
        });
        let client = netsim::node::ipv4::nat(Ipv4NatBuilder::default(), client);

        let router = netsim::node::ipv4::router((rendezvous_server1, rendezvous_server2, client));
        let (spawn_complete, _ipv4_plug) =
            netsim::spawn::ipv4_tree(&network.handle(), Ipv4Range::global(), router);

        let _ = unwrap!(evloop.run(spawn_complete));
    }

    #[test]
    fn it_properly_detects_endpoint_dependent_mapping() {
        let mut evloop = unwrap!(Core::new());
        let handle = evloop.handle();
        let network = Network::new(&handle);

        let (client_drop_tx1, client_drop_rx1) = future_utils::drop_notify();
        let (client_drop_tx2, client_drop_rx2) = future_utils::drop_notify();
        let (client_drop_tx3, client_drop_rx3) = future_utils::drop_notify();
        let (server1_info_tx, server1_info_rx) = oneshot::channel();
        let (server2_info_tx, server2_info_rx) = oneshot::channel();
        let (server3_info_tx, server3_info_rx) = oneshot::channel();

        let rendezvous_server1 = make_stun_server(server1_info_tx, client_drop_rx1);
        let rendezvous_server2 = make_stun_server(server2_info_tx, client_drop_rx2);
        let rendezvous_server3 = make_stun_server(server3_info_tx, client_drop_rx3);

        let client = netsim::node::ipv4::machine(|_ip| {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();

            let task = server1_info_rx
                .map_err(|e| panic!(e))
                .and_then(|server1_info| {
                    server2_info_rx
                        .map_err(|e| panic!(e))
                        .map(move |server2_info| (server1_info, server2_info))
                }).and_then(|(server1_info, server2_info)| {
                    server3_info_rx
                        .map_err(|e| panic!(e))
                        .map(move |server3_info| (server1_info, server2_info, server3_info))
                }).and_then(|(server1_info, server2_info, server3_info)| {
                    let config = unwrap!(ConfigFile::new_temporary());
                    unwrap!(config.write()).hard_coded_contacts =
                        vec![server1_info, server2_info, server3_info];
                    let (our_pk, our_sk) = gen_encrypt_keypair();

                    Service::with_config(&handle, config, our_sk, our_pk)
                        .and_then(|service| service.probe_nat())
                        .and_then(|nat_type| {
                            assert_eq!(nat_type, NatType::EDM);
                            drop(client_drop_tx1);
                            drop(client_drop_tx2);
                            drop(client_drop_tx3);
                            Ok(())
                        })
                });
            unwrap!(evloop.run(task));
        });
        let client = netsim::node::ipv4::nat(Ipv4NatBuilder::default().symmetric(), client);

        let router = netsim::node::ipv4::router((
            rendezvous_server1,
            rendezvous_server2,
            rendezvous_server3,
            client,
        ));
        let (spawn_complete, _ipv4_plug) =
            netsim::spawn::ipv4_tree(&network.handle(), Ipv4Range::global(), router);

        let _ = unwrap!(evloop.run(spawn_complete));
    }
}
