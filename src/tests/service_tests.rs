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
use net::peer;
use p2p::{self, Protocol, query_public_addr};
use priv_prelude::*;
use service::Service;
use std::time::Duration;
use tokio_core::reactor::Core;
use tokio_io;
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
fn bootstrap_using_service_discovery() {
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
    let mut service2 = service_with_config(&mut evloop, config);
    let peer = unwrap!(evloop.run(service2.bootstrap(
        HashSet::new(),
        true,
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

#[test]
fn service_responds_to_tcp_echo_address_requests() {
    let mut event_loop = unwrap!(Core::new());
    let handle = event_loop.handle();

    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0")];
    let service = service_with_config(&mut event_loop, config);
    let listener = unwrap!(event_loop.run(service.start_listening().first_ok()));
    let listener_addr = listener.addr().unspecified_to_localhost().inner();

    let resp = event_loop.run(query_public_addr(
        Protocol::Tcp,
        &addr!("0.0.0.0:0"),
        &p2p::PeerInfo::new(listener_addr, service.public_key()),
        &handle,
    ));
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
    let service1_priv_conn_info = unwrap!(evloop.run(service1.prepare_connection_info()));
    let service1_pub_conn_info = service1_priv_conn_info.to_pub_connection_info();

    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0")];
    let service2 = service_with_config(&mut evloop, config);
    let _listener2 = unwrap!(evloop.run(service2.start_listening().first_ok()));
    let service2_priv_conn_info = unwrap!(evloop.run(service2.prepare_connection_info()));
    let service2_pub_conn_info = service2_priv_conn_info.to_pub_connection_info();

    let connect = service1
        .connect(service1_priv_conn_info, service2_pub_conn_info)
        .join(service2.connect(
            service2_priv_conn_info,
            service1_pub_conn_info,
        ));
    let (service1_peer, service2_peer) = unwrap!(evloop.run(connect));

    let data_len = MAX_PAYLOAD_SIZE + 10;
    let mut data = vec![1u8; data_len];
    data[0] = ((data_len >> 24) & 0xff) as u8;
    data[1] = ((data_len >> 16) & 0xff) as u8;
    data[2] = ((data_len >> 8) & 0xff) as u8;
    data[3] = (data_len & 0xff) as u8;
    let send_data = service1_peer
        .socket()
        .into_inner()
        .map_err(|e| panic!("Failed to extract peer inner stream: {}", e))
        .map(|framed_stream| framed_stream.into_inner())
        .and_then(|peer_stream| {
            tokio_io::io::write_all(peer_stream, data).map(|(peer_stream, _data)| peer_stream)
        });
    let recv_data = service2_peer.into_future().then(|_result| Ok(()));
    let res = evloop.run(send_data.join(recv_data));
    match res {
        // On Mac OS, when remote peer gets too big packet, it terminates connection and
        // tokio_io::io::write_all() terminates immediately with broken pipe.
        Err(e) => {
            let broken_pipe = match e.kind() {
                io::ErrorKind::BrokenPipe => true,
                _ => false,
            };
            assert!(broken_pipe);
        }
        // On other OSes we need to try to receive to get connection reset error.
        Ok((service1_peer_stream, _)) => {
            let recv_response = tokio_io::io::read_to_end(service1_peer_stream, Vec::new())
                .map(|_| ());
            let res = evloop.run(recv_response);
            let connection_closed = match res {
                Err(e) => {
                    match e.kind() {
                        io::ErrorKind::ConnectionReset => true,
                        _ => false,
                    }
                }
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
            .and_then(|stream| {
                tokio_io::io::write_all(stream, b"\x00\x00\x00\x0brandom data")
            })
            .and_then(|(stream, _buf)| {
                tokio_io::io::read_to_end(stream, Vec::new())
            })
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
        let handle = evloop.handle();

        let service1 = service_with_tmp_config(&mut evloop);
        let _listener1 = unwrap!(evloop.run(service1.start_listening().first_ok()));
        let service1_priv_conn_info = unwrap!(evloop.run(service1.prepare_connection_info()));
        let service1_pub_conn_info = service1_priv_conn_info.to_pub_connection_info();

        let service2 = service_with_tmp_config(&mut evloop);
        let _listener2 = unwrap!(evloop.run(service2.start_listening().first_ok()));
        let service2_priv_conn_info = unwrap!(evloop.run(service2.prepare_connection_info()));
        let service2_pub_conn_info = service2_priv_conn_info.to_pub_connection_info();

        let connect = service1
            .connect(service1_priv_conn_info, service2_pub_conn_info)
            .join(service2.connect(
                service2_priv_conn_info,
                service1_pub_conn_info,
            ));

        let (service1_peer, service2_peer) = unwrap!(evloop.run(connect));
        let service2_peer = {
            let id = service2_peer.uid();
            let kind = service2_peer.kind();
            let mut peer1_socket = service2_peer.socket();
            peer1_socket.use_crypto_ctx(CryptoContext::null());
            peer::from_handshaken_socket(&handle, peer1_socket, id, kind)
        };

        let send_text = service2_peer.send((1, vec![1, 2, 3])) // let's send unencrypted data
            .and_then(|peer| {
                peer.into_future()
                    .map_err(|(e, _peer)| panic!("service2 failed to receive {}", e))
                    .map(|(data_opt, _peer)| unwrap!(data_opt))
            })
            .join(service1_peer.into_future()
                .map_err(|(e, _peer)| e) // we'll return error for assertion
                .and_then(|(data_opt, peer)| {
                    peer.send((1, vec![3, 2, 1])).map(move |_peer| unwrap!(data_opt))
                })
            );
        let res = evloop.run(send_text);

        let failed_to_decrypt_plaintext = match res {
            Err(e) => {
                match e {
                    PeerError::Decrypt(_) => true,
                    _ => false,
                }
            }
            _ => false,
        };
        assert!(failed_to_decrypt_plaintext);
    }
}

/*

    Things to test:

    are bootstrap blacklists respected?
    are external reachability requirements respected?
    are whitelists respected?

    can we connect with no listeners? - not really testable over loopback

*/
