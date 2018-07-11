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

use config::{DevConfigSettings, PeerInfo};
use env_logger;
use future_utils::bi_channel;
use futures::stream;
use priv_prelude::*;
use service::Service;
use std::time::Duration;
use tokio_core::reactor::Core;
use tokio_io;
use util;

fn service_with_config(event_loop: &mut Core, config: ConfigFile) -> Service {
    let loop_handle = event_loop.handle();
    unwrap!(event_loop.run(Service::with_config(&loop_handle, config, SecretId::new(),)))
}

fn service_with_tmp_config(event_loop: &mut Core) -> Service {
    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0"), utp_addr!("0.0.0.0:0")];
    service_with_config(event_loop, config)
}

mod bootstrap {
    use super::*;

    fn bootstrap_using_hard_coded_contacts(listen_addr: PaAddr) {
        let mut event_loop = unwrap!(Core::new());
        let loop_handle = event_loop.handle();

        let config = unwrap!(ConfigFile::new_temporary());
        unwrap!(config.write()).listen_addresses = vec![listen_addr];
        let mut service1 = service_with_config(&mut event_loop, config);
        let listener1 = unwrap!(event_loop.run(service1.start_listening().first_ok()));
        let service1_addr = listener1.addr().unspecified_to_localhost();

        loop_handle.spawn(
            service1
                .bootstrap_acceptor()
                .for_each(|_| Ok(()))
                .then(|_| Ok(())),
        );

        let config2 = unwrap!(ConfigFile::new_temporary());
        unwrap!(config2.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        unwrap!(config2.write()).hard_coded_contacts =
            vec![PeerInfo::new(service1_addr, service1.public_id())];
        let mut service2 =
            unwrap!(event_loop.run(Service::with_config(&loop_handle, config2, SecretId::new(),)));

        let service_discovery = false;
        let peer = unwrap!(event_loop.run(service2.bootstrap(
            HashSet::new(),
            service_discovery,
            CrustUser::Client,
        )));

        assert_eq!(peer.public_id(), &service1.public_id());
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
        let mut evloop = unwrap!(Core::new());

        let config = unwrap!(ConfigFile::new_temporary());
        {
            let mut conf_rw = unwrap!(config.write());
            conf_rw.listen_addresses = vec![tcp_addr!("0.0.0.0:0")];
            conf_rw.service_discovery_port = Some(0);
        }
        let mut service1 = service_with_config(&mut evloop, config);
        let _listeners1 = unwrap!(evloop.run(service1.start_listening().collect()));
        let service_discovery = unwrap!(service1.start_service_discovery());
        evloop.handle().spawn(
            service1
                .bootstrap_acceptor()
                .for_each(|_| Ok(()))
                .then(|_| Ok(())),
        );

        let config = unwrap!(ConfigFile::new_temporary());
        unwrap!(config.write()).service_discovery_port = Some(service_discovery.port());
        unwrap!(config.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        let mut service2 = service_with_config(&mut evloop, config);
        let peer =
            unwrap!(evloop.run(service2.bootstrap(HashSet::new(), true, CrustUser::Client,)));

        assert_eq!(peer.public_id(), &service1.public_id());
    }

    #[test]
    fn connected_peer_is_inserted_into_bootstrap_cache() {
        let mut evloop = unwrap!(Core::new());
        let handle = evloop.handle();

        let mut service1 = service_with_tmp_config(&mut evloop);
        let listeners = unwrap!(evloop.run(service1.start_listening().collect()));
        let service1_addr0 = listeners[0].addr().unspecified_to_localhost();

        handle.spawn(
            service1
                .bootstrap_acceptor()
                .for_each(|_| Ok(()))
                .then(|_| Ok(())),
        );

        let config2 = unwrap!(ConfigFile::new_temporary());
        unwrap!(config2.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        unwrap!(config2.write()).hard_coded_contacts =
            vec![PeerInfo::new(service1_addr0, service1.public_id())];
        let mut service2 =
            unwrap!(evloop.run(Service::with_config(&handle, config2, SecretId::new(),)));

        let service_discovery = false;
        let peer = unwrap!(evloop.run(service2.bootstrap(
            HashSet::new(),
            service_discovery,
            CrustUser::Client,
        )));

        let peer_info = PeerInfo::new(unwrap!(peer.addr()), service1.public_id());
        assert!(service2.bootstrap_cache().peers().contains(&peer_info));
    }
}

mod direct_connections {
    use super::*;

    fn connect_on_localhost(listen_addr: PaAddr) {
        let mut event_loop = unwrap!(Core::new());

        let config1 = unwrap!(ConfigFile::new_temporary());
        let mut dev_cfg = DevConfigSettings::default();
        dev_cfg.disable_rendezvous_connections = true;
        unwrap!(config1.write()).dev = Some(dev_cfg);
        unwrap!(config1.write()).listen_addresses = vec![listen_addr];
        let config2 = config1.clone();

        let service1 = service_with_config(&mut event_loop, config1);
        let _listener1 = unwrap!(event_loop.run(service1.start_listening().first_ok()));

        let service2 = service_with_config(&mut event_loop, config2);
        let _listener2 = unwrap!(event_loop.run(service2.start_listening().first_ok()));

        let (ci_channel1, ci_channel2) = bi_channel::unbounded();
        let connect = service1
            .connect(ci_channel1)
            .join(service2.connect(ci_channel2));
        let (service1_peer, service2_peer) = unwrap!(event_loop.run(connect));
        assert_eq!(service1_peer.public_id(), &service2.public_id());
        assert_eq!(service2_peer.public_id(), &service1.public_id());
    }

    #[test]
    fn tcp_connections_on_localhost() {
        connect_on_localhost(tcp_addr!("0.0.0.0:0"));
    }

    #[test]
    fn utp_connections_on_localhost() {
        connect_on_localhost(utp_addr!("0.0.0.0:0"));
    }

    #[test]
    fn localhost_when_only_one_peer_is_directly_accessible() {
        let mut evloop = unwrap!(Core::new());
        let handle = evloop.handle();

        let config1 = unwrap!(ConfigFile::new_temporary());
        let mut dev_cfg = DevConfigSettings::default();
        dev_cfg.disable_rendezvous_connections = true;
        unwrap!(config1.write()).dev = Some(dev_cfg.clone());
        unwrap!(config1.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0")];

        let service1 = service_with_config(&mut evloop, config1);
        let _listener1 = unwrap!(evloop.run(service1.start_listening().first_ok()));

        let config2 = unwrap!(ConfigFile::new_temporary());
        unwrap!(config2.write()).dev = Some(dev_cfg);
        unwrap!(config2.write()).listen_addresses = vec![];
        let service2 = service_with_config(&mut evloop, config2);

        let (ci_channel1, ci_channel2) = bi_channel::unbounded();
        let (service2_peer, service1_peer) = unwrap!(
            evloop.run(
                service2
                    .connect(ci_channel2)
                    .join(service1.connect(ci_channel1))
                    .with_timeout(Duration::from_secs(5), &handle)
                    .map(|res_opt| unwrap!(res_opt, "Failed to connect within reasonable time")),
            )
        );
        assert_eq!(service1_peer.public_id(), &service2.public_id());
        assert_eq!(service2_peer.public_id(), &service1.public_id());
    }

    #[test]
    fn connected_peer_is_inserted_into_bootstrap_cache() {
        let mut evloop = unwrap!(Core::new());

        let config1 = unwrap!(ConfigFile::new_temporary());
        let mut dev_cfg = DevConfigSettings::default();
        dev_cfg.disable_rendezvous_connections = true;
        unwrap!(config1.write()).dev = Some(dev_cfg.clone());
        unwrap!(config1.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0")];
        unwrap!(config1.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        let service1 = service_with_config(&mut evloop, config1);
        let _listener1 = unwrap!(evloop.run(service1.start_listening().first_ok()));

        let config2 = unwrap!(ConfigFile::new_temporary());
        unwrap!(config2.write()).dev = Some(dev_cfg);
        unwrap!(config2.write()).listen_addresses = vec![];
        unwrap!(config2.write()).bootstrap_cache_name = Some(util::bootstrap_cache_tmp_file());
        let service2 = service_with_config(&mut evloop, config2);

        let (ci_channel1, ci_channel2) = bi_channel::unbounded();
        let connect = service2
            .connect(ci_channel2)
            .join(service1.connect(ci_channel1));
        let (service2_peer, _service1_peer) = unwrap!(evloop.run(connect));

        let service2_peer = PeerInfo::new(unwrap!(service2_peer.addr()), service1.public_id());
        assert!(service2.bootstrap_cache().peers().contains(&service2_peer));
    }
}

// None of the services in this test has listeners, therefore peer-to-peer connections are made.
#[test]
fn p2p_connections_on_localhost() {
    let _ = env_logger::init();

    let mut event_loop = unwrap!(Core::new());

    let config = unwrap!(ConfigFile::new_temporary());
    let service1 = service_with_config(&mut event_loop, config);

    let config = unwrap!(ConfigFile::new_temporary());
    let service2 = service_with_config(&mut event_loop, config);

    let (ci_channel1, ci_channel2) = bi_channel::unbounded();
    let connect = service1
        .connect(ci_channel1)
        .join(service2.connect(ci_channel2))
        .with_timeout(Duration::from_secs(10), &event_loop.handle())
        .map(|res_opt| unwrap!(res_opt, "p2p connection timed out"));

    let (service1_peer, service2_peer) = unwrap!(event_loop.run(connect));
    assert_eq!(service1_peer.public_id(), &service2.public_id());
    assert_eq!(service2_peer.public_id(), &service1.public_id());
}

#[test]
fn peer_shutdown_closes_remote_peer_too() {
    let mut event_loop = unwrap!(Core::new());
    let loop_handle = event_loop.handle();

    let service1 = service_with_tmp_config(&mut event_loop);
    let _listener1 = unwrap!(event_loop.run(service1.start_listening().first_ok()));

    let service2 = service_with_tmp_config(&mut event_loop);
    let _listener2 = unwrap!(event_loop.run(service2.start_listening().first_ok()));

    let (ci_channel1, ci_channel2) = bi_channel::unbounded();
    let connect = service1
        .connect(ci_channel1)
        .join(service2.connect(ci_channel2));
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

    let service2 = service_with_tmp_config(&mut event_loop);
    let _listener2 = unwrap!(event_loop.run(service2.start_listening().first_ok()));

    let (ci_channel1, ci_channel2) = bi_channel::unbounded();
    let connect = service1
        .connect(ci_channel1)
        .join(service2.connect(ci_channel2));
    let (service1_peer, service2_peer) = unwrap!(event_loop.run(connect));

    const NUM_MESSAGES: u64 = 100;
    let random_data = || {
        const MAX_DATA_SIZE: usize = 512;
        (0..NUM_MESSAGES)
            .map(|_| Bytes::from(util::random_vec(MAX_DATA_SIZE)))
            .collect::<Vec<_>>()
    };

    let data1 = random_data();
    let data2 = random_data();

    let spawn_sending = |data, peer: Peer| {
        let (peer_sink, peer_stream) = peer.split();
        let data_stream = stream::iter_ok::<_, ()>(data).map_err(|_| PeerError::Destroyed);
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

#[test]
fn service_responds_to_tcp_echo_address_requests() {
    let mut event_loop = unwrap!(Core::new());
    let handle = event_loop.handle();

    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0")];
    let service = service_with_config(&mut event_loop, config);
    let listener = unwrap!(event_loop.run(service.start_listening().first_ok()));
    let listener_addr = listener.addr().unspecified_to_localhost().inner();

    let addr_querier = PaTcpAddrQuerier::new(&listener_addr, service.public_id());
    let resp = event_loop.run(addr_querier.query(&addr!("0.0.0.0:0"), &handle));
    let our_addr = unwrap!(resp);

    assert_eq!(our_addr.ip(), ipv4!("127.0.0.1"));
}

#[test]
fn when_peer_sends_too_big_tcp_packet_other_peer_closes_connection() {
    let mut evloop = unwrap!(Core::new());

    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0")];
    let service1 = service_with_config(&mut evloop, config);
    let _listener1 = unwrap!(evloop.run(service1.start_listening().first_ok()));

    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0")];
    let service2 = service_with_config(&mut evloop, config);
    let _listener2 = unwrap!(evloop.run(service2.start_listening().first_ok()));

    let (ci_channel1, ci_channel2) = bi_channel::unbounded();
    let connect = service1
        .connect(ci_channel1)
        .join(service2.connect(ci_channel2));
    let (service1_peer, service2_peer) = unwrap!(evloop.run(connect));

    let data_len = ::MAX_PAYLOAD_SIZE + 10;
    let mut data = vec![1u8; data_len];
    data[0] = ((data_len >> 24) & 0xff) as u8;
    data[1] = ((data_len >> 16) & 0xff) as u8;
    data[2] = ((data_len >> 8) & 0xff) as u8;
    data[3] = (data_len & 0xff) as u8;
    let peer_stream = service1_peer.into_pa_stream().into_tcp_stream();
    let send_data =
        { tokio_io::io::write_all(peer_stream, data).map(|(peer_stream, _data)| peer_stream) };
    let recv_data = service2_peer.into_future().then(|_result| Ok(()));
    let res = evloop.run(send_data.join(recv_data));
    match res {
        // On Mac OS, when remote peer gets too big packet, it terminates connection and
        // tokio_io::io::write_all() terminates immediately with broken pipe.
        Err(e) => {
            match e.kind() {
                io::ErrorKind::BrokenPipe => (),
                io::ErrorKind::ConnectionReset => (),
                _ => panic!("unexpected error: {}", e),
            };
        }
        // On other OSes we need to try to receive to get connection reset error.
        Ok((service1_peer_stream, _)) => {
            let recv_response =
                tokio_io::io::read_to_end(service1_peer_stream, Vec::new()).map(|_| ());
            let res = evloop.run(recv_response);
            let connection_closed = match res {
                Err(e) => match e.kind() {
                    io::ErrorKind::ConnectionReset => true,
                    _ => false,
                },
                _ => false,
            };
            assert!(connection_closed);
        }
    };
}

mod encryption {
    use super::*;

    #[test]
    fn service_closes_tcp_connection_when_random_plaintext_is_sent() {
        let mut evloop = unwrap!(Core::new());
        let handle = evloop.handle();

        let config = unwrap!(ConfigFile::new_temporary());
        unwrap!(config.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0")];
        let service = service_with_config(&mut evloop, config);
        let listener = unwrap!(evloop.run(service.start_listening().first_ok()));
        let listener_addr = listener.addr().unspecified_to_localhost().inner();

        let send_text = TcpStream::connect(&listener_addr, &handle)
            .and_then(|stream| tokio_io::io::write_all(stream, b"\x00\x00\x00\x0brandom data"))
            .and_then(|(stream, _buf)| tokio_io::io::read_to_end(stream, Vec::new()))
            .map(|(_stream, buf)| buf);
        let resp = unwrap!(evloop.run(send_text));

        assert_eq!(resp.len(), 0);
    }

    #[test]
    fn service_sends_nothing_back_to_udp_endpoint_when_random_plaintext_is_sent() {
        let mut evloop = unwrap!(Core::new());
        let handle = evloop.handle();

        let config = unwrap!(ConfigFile::new_temporary());
        unwrap!(config.write()).listen_addresses = vec![utp_addr!("0.0.0.0:0")];
        let service = service_with_config(&mut evloop, config);
        let listener = unwrap!(evloop.run(service.start_listening().first_ok()));
        let listener_addr = listener.addr().unspecified_to_localhost().inner();

        let socket = unwrap!(UdpSocket::bind(&addr!("0.0.0.0:0"), &handle));
        let send_text = socket
            .send_dgram(b"random data", listener_addr)
            .and_then(|(socket, _buf)| socket.recv_dgram(Vec::new()))
            .map(|(_socket, buf, _bytes_received, _from)| buf)
            .with_timeout(Duration::from_secs(2), &handle);
        let resp = unwrap!(evloop.run(send_text));

        let timed_out = resp.is_none();
        assert!(timed_out);
    }

    #[test]
    fn when_peer_sends_unencrypted_traffic_other_peer_closes_connection_with_error() {
        let mut evloop = unwrap!(Core::new());

        let service1 = service_with_tmp_config(&mut evloop);
        let _listener1 = unwrap!(evloop.run(service1.start_listening().first_ok()));

        let config = unwrap!(ConfigFile::new_temporary());
        unwrap!(config.write()).listen_addresses = vec![utp_addr!("0.0.0.0:0")];
        unwrap!(config.write()).dev = Some(DevConfigSettings {
            disable_tcp: true,
            ..DevConfigSettings::default()
        });
        let service2 = service_with_config(&mut evloop, config);
        let _listener2 = unwrap!(evloop.run(service2.start_listening().first_ok()));

        let (ci_channel1, ci_channel2) = bi_channel::unbounded();
        let connect = service1
            .connect(ci_channel1)
            .join(service2.connect(ci_channel2));
        let (service1_peer, service2_peer) = unwrap!(evloop.run(connect));
        let service2_tcp = service2_peer.into_pa_stream().into_utp_stream();

        let mut data = util::random_vec(1024 + 4);
        data[0..4].clone_from_slice(&[0, 0, 4, 0]);

        evloop
            .run({
                tokio_io::io::write_all(service2_tcp, data)
                    .map_err(|e| panic!("error writing: {}", e))
                    .join({
                        service1_peer
                            .into_future()
                            .map(|x| panic!("unexpected success: {:?}", x))
                            .or_else(|(e, _service1_peer)| match e {
                                PeerError::Read(_e) => Ok(()),
                                e => panic!("unexpected error: {}", e),
                            })
                    })
                    .map(|(_service2_tcp, ())| ())
            })
            .void_unwrap()
    }
}

mod when_no_message_received_within_inactivity_period {
    use super::*;

    fn connect_and_do_nothing(
        evloop: &mut Core,
        listener_addr: PaAddr,
        heartbeats_enabled: bool,
    ) -> impl Future<Item = (), Error = PeerError> {
        let config1 = unwrap!(ConfigFile::new_temporary());
        let mut dev_cfg = DevConfigSettings::default();
        dev_cfg.disable_rendezvous_connections = true;
        unwrap!(config1.write()).dev = Some(dev_cfg);
        unwrap!(config1.write()).listen_addresses = vec![listener_addr];
        let config2 = config1.clone();

        let service1 = service_with_config(evloop, config1);
        let _listener1 = unwrap!(evloop.run(service1.start_listening().first_ok()));

        let service2 = service_with_config(evloop, config2);
        let _listener2 = unwrap!(evloop.run(service2.start_listening().first_ok()));

        let (ci_channel1, ci_channel2) = bi_channel::unbounded();
        let connect = service1
            .connect(ci_channel1)
            .join(service2.connect(ci_channel2));
        let (mut service1_peer, mut service2_peer) = unwrap!(evloop.run(connect));

        if !heartbeats_enabled {
            service1_peer.disable_heartbeats();
            service2_peer.disable_heartbeats();
        }

        // make sure we poll both peers so both of them exchange heartbeats
        service1_peer
            .for_each(|_data| Ok(()))
            .join(service2_peer.for_each(|_data| Ok(())))
            .and_then(|(_, _)| Ok(()))
    }

    #[test]
    fn when_heartbeats_turned_off_tcp_peer_yields_error() {
        let mut evloop = unwrap!(Core::new());
        let connect = connect_and_do_nothing(&mut evloop, tcp_addr!("127.0.0.1:0"), false);
        match evloop.run(connect) {
            Err(PeerError::InactivityTimeout) => (),
            res => panic!("Unexpected result from peer: {:?}", res),
        }
    }

    #[test]
    fn when_heartbeats_turned_off_utp_peer_yields_error() {
        let mut evloop = unwrap!(Core::new());
        let connect = connect_and_do_nothing(&mut evloop, utp_addr!("127.0.0.1:0"), false);
        match evloop.run(connect) {
            Err(PeerError::InactivityTimeout) => (),
            res => panic!("Unexpected result from peer: {:?}", res),
        }
    }

    #[test]
    fn when_heartbeats_exchanging_tcp_peer_stays_alive() {
        let mut evloop = unwrap!(Core::new());
        let handle = evloop.handle();

        let connect = connect_and_do_nothing(&mut evloop, tcp_addr!("127.0.0.1:0"), true)
            .with_timeout(Duration::from_secs(2), &handle);
        let res = unwrap!(evloop.run(connect));

        let timedout = res.is_none();
        assert!(timedout);
    }

    #[test]
    fn when_heartbeats_exchanging_utp_peer_stays_alive() {
        let mut evloop = unwrap!(Core::new());
        let handle = evloop.handle();

        let connect = connect_and_do_nothing(&mut evloop, utp_addr!("127.0.0.1:0"), true)
            .with_timeout(Duration::from_secs(2), &handle);
        let res = unwrap!(evloop.run(connect));

        let timedout = res.is_none();
        assert!(timedout);
    }
}
