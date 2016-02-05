// Copyright 2015 MaidSafe.net limited.
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

use std::io;
use std::sync::mpsc;
use std::sync::atomic::{Ordering, AtomicBool};
use std::thread;
use std::net;
use std::thread::JoinHandle;
use std::sync::{Arc, Mutex};
use std::str::FromStr;
use std::cmp;
use service_discovery::ServiceDiscovery;
use sodiumoxide;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::PublicKey;

use std::net::TcpListener;

use connection::RaiiTcpAcceptor;
use udp_listener::RaiiUdpListener;
use static_contact_info::StaticContactInfo;
use rand;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use itertools::Itertools;
use config_handler::{Config, read_config_file};
use endpoint::{Endpoint, Protocol};
use connection::Connection;
use error::Error;
use ip::SocketAddrExt;
use connection;
use bootstrap;
use bootstrap::RaiiBootstrap;

use event::Event;
use connection_info::{OurConnectionInfo, OurConnectionInfoInner, TheirConnectionInfo,
                      TheirConnectionInfoInner, ConnectionInfoResult,
                      FriendOurConnectionInfo, FriendTheirConnectionInfo};
use socket_addr::{SocketAddr, SocketAddrV4};
use bootstrap_handler::BootstrapHandler;
use utp_connections;

/*
// Mainly used for testing right now
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum UseProtocol {
    TcpOnly,
    UdpOnly,
    TcpUdpBoth,
}
*/

/// A structure representing a connection manager.
///
/// This abstraction has a hidden dependency on a config file. Refer to [the docs for `FileHandler`]
/// (../file_handler/struct.FileHandler.html) and [an example config file flowchart]
/// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf) for more
/// information.
pub struct Service {
    static_contact_info: Arc<Mutex<StaticContactInfo>>,
    peer_contact_infos: Arc<Mutex<Vec<StaticContactInfo>>>,
    service_discovery: ServiceDiscovery<StaticContactInfo>,
    event_tx: ::CrustEventSender,
    bootstrap: RaiiBootstrap,
    use_static_tcp_listener: bool,
    use_static_udp_listener: bool,
    _raii_udp_listener: Option<RaiiUdpListener>,
    _raii_tcp_acceptor: Option<RaiiTcpAcceptor>,
}

impl Service {
    /// Constructs a service. User needs to create an asynchronous channel, and provide
    /// the sender half to this method. Receiver will receive all `Event`s from this library.
    pub fn new(event_tx: ::CrustEventSender,
               service_discovery_port: u16)
               -> Result<Service, Error> {
        Service::new_impl(event_tx, service_discovery_port, true, true)
    }

    fn new_impl(event_tx: ::CrustEventSender,
                service_discovery_port: u16,
                use_static_tcp_listener: bool,
                use_static_udp_listener: bool)
                -> Result<Service, Error> {
        sodiumoxide::init();

        // TODO Use private key once crate is stable
        let (pub_key, _priv_key) = sign::gen_keypair();

        // Form our initial contact info
        let static_contact_info = Arc::new(Mutex::new(StaticContactInfo {
            pub_key: pub_key,
            tcp_acceptors: Vec::new(),
            udp_listeners: Vec::new(),
        }));

        let cloned_contact_info = static_contact_info.clone();
        let generator = move || unwrap_result!(cloned_contact_info.lock()).clone();
        let service_discovery = try!(ServiceDiscovery::new_with_generator(service_discovery_port,
                                                                          generator));

        // Form initial peer contact infos - these will also contain echo-service addrs.
        let bootstrap_contacts = try!(bootstrap::get_known_contacts(&service_discovery, &pub_key));
        let peer_contact_infos = Arc::new(Mutex::new(bootstrap_contacts));

        // Start the TCP Acceptor
        let raii_tcp_acceptor = if use_static_tcp_listener {
            Some(try!(connection::start_tcp_accept(0,
                                                   static_contact_info.clone(),
                                                   peer_contact_infos.clone(),
                                                   event_tx.clone())))
        } else {
            None
        };

        // Start the UDP Listener
        let udp_listener = if use_static_udp_listener {
            Some(try!(RaiiUdpListener::new(0,
                                           static_contact_info.clone(),
                                           peer_contact_infos.clone(),
                                           event_tx.clone())))
        } else {
            None
        };

        let bootstrap = RaiiBootstrap::new(static_contact_info.clone(),
                                           peer_contact_infos.clone(),
                                           event_tx.clone());

        let service = Service {
            static_contact_info: static_contact_info,
            peer_contact_infos: peer_contact_infos,
            service_discovery: service_discovery,
            event_tx: event_tx,
            bootstrap: bootstrap,
            use_static_tcp_listener: use_static_tcp_listener,
            use_static_udp_listener: use_static_udp_listener,
            _raii_udp_listener: udp_listener,
            _raii_tcp_acceptor: raii_tcp_acceptor,
        };

        Ok(service)
    }

    /// Stop the bootstraping procedure
    pub fn stop_bootstrap(&mut self) {
        self.bootstrap.stop();
    }

    /// Enable or Disable listening to peers trying to find us. The return value indicates
    /// successful registration of the request.
    pub fn set_listen_for_peers(&self, listen: bool) -> bool {
        self.service_discovery.set_listen_for_peers(listen)
    }

    /// Get the hole punch servers addresses of nodes that we're connected to ordered by how likely
    /// they are to be on a seperate network.
    pub fn get_ordered_helping_nodes(&self) -> Vec<SocketAddr> {
        unimplemented!()
    }

    /// Opens a connection to a remote peer. `public_endpoint` is the endpoint
    /// of the remote peer. `udp_socket` is a socket whose public address will
    /// be used by the other peer.
    ///
    /// A rendezvous connection setup is different to the traditional BSD socket
    /// setup in which there is no client or server side. Both ends create a
    /// socket and send somehow its public address to the other peer. Once both
    /// ends know each other address, both must call this function passing the
    /// socket which possess the address used by the other peer and passing the
    /// other peer's address.
    ///
    /// Only UDP-based protocols are supported. This means that you must use a
    /// uTP endpoint or nothing will happen.
    ///
    /// On success `Event::OnConnect` with connected `Endpoint` will
    /// be sent to the event channel. On failure, nothing is reported. Failed
    /// attempts are not notified back up to the caller. If the caller wants to
    /// know of a failed attempt, it must maintain a record of the attempt
    /// itself which times out if a corresponding
    /// `Event::OnConnect` isn't received. See also [Process for
    /// Connecting]
    /// (https://github.com/maidsafe/crust/blob/master/docs/connect.md) for
    /// details on handling of connect in different protocols.
    pub fn connect(&self,
                   our_connection_info: OurConnectionInfo,
                   their_connection_info: TheirConnectionInfo) {
        if let Some(msg) = {
            if their_connection_info.get_inner().udp_addrs.is_empty() {
                Some("No rendezvous address supplied. Direct connections not yet supported.")
            } else {
                None
            }
        } {
            let err = io::Error::new(io::ErrorKind::Other, msg);
            let ev = Event::NewConnection {
                connection: Err(err),
                their_pub_key: their_connection_info.get_pub_key().clone(),
            };
            let _ = self.event_tx.send(ev);
            return;
        }

        let event_tx = self.event_tx.clone();
        let our_pub_key = unwrap_result!(self.static_contact_info.lock()).pub_key.clone();

        // TODO connect to all the socket addresses of peer in parallel
        let _joiner = thread!("PeerConnectionThread", move || {
            let their_pub_key = their_connection_info.get_pub_key().clone();
            let our_connection_info_inner = our_connection_info.take_inner();
            let their_connection_info_inner = their_connection_info.take_inner();
            let (udp_socket, result_addr) =
                ::utp_connections::blocking_udp_punch_hole(our_connection_info_inner.udp_socket,
                                                           our_connection_info_inner.secret,
                                                           their_connection_info_inner.secret,
                                                           their_connection_info_inner.udp_addrs[0]
                                                               .clone());
            let public_endpoint = match result_addr {
                Ok(addr) => addr,
                Err(e) => {
                    let ev = Event::NewConnection {
                        connection: Err(e),
                        their_pub_key: their_pub_key,
                    };
                    let _ = event_tx.send(ev);
                    return;
                }
            };

            let _ = event_tx.send(Event::NewConnection {
                connection: connection::utp_rendezvous_connect(udp_socket,
                                                               public_endpoint,
                                                               their_pub_key.clone(),
                                                               event_tx.clone()),
                their_pub_key: their_pub_key,
            });
        });
    }

    /// Lookup a mapped udp socket based on result_token
    pub fn prepare_connection_info(&mut self, result_token: u32) {
        let mut peer_udp_listeners = Vec::with_capacity(100);
        for peer_contact_info in &*unwrap_result!(self.peer_contact_infos.lock()) {
            peer_udp_listeners.extend(peer_contact_info.udp_listeners.clone());
        }

        let our_static_contact_info = self.static_contact_info.clone();
        let peer_contact_infos = self.peer_contact_infos.clone();
        let event_tx = self.event_tx.clone();

        let _joiner = thread!("PrepareContactInfo", move || {
            let result_external_socket = utp_connections::external_udp_socket(peer_udp_listeners);
            let (udp_socket, udp_addrs) = match result_external_socket {
                Ok(x) => x,
                Err(e) => {
                    let _ = event_tx.send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                        result_token: result_token,
                        result: Err(e),
                    }));
                    return;
                },
            };

            let result_tcp_acceptor = connection::start_tcp_accept(0,
                                                                   our_static_contact_info.clone(),
                                                                   peer_contact_infos,
                                                                   event_tx.clone());
            /*
            let raii_tcp_acceptor = match result_tcp_acceptor {
                Ok(x) => x,
                Err(e) => {
                    let _ = event_tx.send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                        result_token: result_token,
                        result: Err(e),
                    }));
                    return;
                },
            };
            */

            let send = Event::ConnectionInfoPrepared(ConnectionInfoResult {
                result_token: result_token,
                result: Ok(OurConnectionInfo::new(OurConnectionInfoInner {
                    secret: rand::random(),
                    //raii_tcp_acceptor: unimplemented!(),
                    //tcp_addrs: unimplemented!(),
                        // wny are we starting a tcp acceptor?
                        // Are tcp acceptors being used to do rendezvous connections now?
                        // coz that doesn't make sense
                    
                    udp_socket: udp_socket,
                    udp_addrs: udp_addrs,
                    static_contact_info: unwrap_result!(our_static_contact_info.lock()).clone(),
                })),
            });
            let _ = event_tx.send(send);
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use event::Event;
    use endpoint::Protocol;

    use std::sync::mpsc;
    use std::sync::mpsc::Receiver;

    use maidsafe_utilities::event_sender::{MaidSafeObserver, MaidSafeEventCategory};

    fn get_event_sender()
        -> (::CrustEventSender,
            Receiver<MaidSafeEventCategory>,
            Receiver<Event>)
    {
        let (category_tx, category_rx) = mpsc::channel();
        let event_category = MaidSafeEventCategory::CrustEvent;
        let (event_tx, event_rx) = mpsc::channel();

        (MaidSafeObserver::new(event_tx, event_category, category_tx),
         category_rx,
         event_rx)
    }

    #[test]
    fn start_stop_service() {
        let (event_sender, _, _) = get_event_sender();
        let _service = unwrap_result!(Service::new(event_sender, 44444));
    }

    fn two_services_bootstrap_communicate_and_exit(port: u16, use_tcp: bool, use_udp: bool) {
        assert!(use_tcp || use_udp);

        let (event_sender_0, category_rx_0, event_rx_0) = get_event_sender();
        let (event_sender_1, category_rx_1, event_rx_1) = get_event_sender();

        let service_0 = unwrap_result!(Service::new_impl(event_sender_0, port, use_tcp, use_udp));
        // let service_0 finish bootstrap - since it is the zero state, it should not find any peer
        // to bootstrap
        {
            let event_rxd = unwrap_result!(event_rx_0.recv());
            match event_rxd {
                Event::BootstrapFinished => (),
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        }
        assert!(service_0.set_listen_for_peers(true));

        let service_1 = unwrap_result!(Service::new_impl(event_sender_1, port, use_tcp, use_udp));
        // let service_1 finish bootstrap - it should bootstrap off service_0
        let (mut connection_1_to_0, pub_key_0) = {
            let event_rxd = unwrap_result!(event_rx_1.recv());
            match event_rxd {
                Event::NewConnection { connection: Ok(connection_obj), their_pub_key } => {
                    (connection_obj, their_pub_key)
                }
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        };

        // now service_1 should get BootstrapFinished
        {
            let event_rxd = unwrap_result!(event_rx_1.recv());
            match event_rxd {
                Event::BootstrapFinished => (),
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        }

        // service_0 should have received service_1's connection bootstrap connection by now
        let (mut connection_0_to_1, pub_key_1) = match unwrap_result!(event_rx_0.recv()) {
            Event::NewConnection { connection: Ok(connection_obj), their_pub_key } => {
                (connection_obj, their_pub_key)
            }
            _ => panic!("0 Should have got a new connection from 1."),
        };

        if use_tcp {
            assert_eq!(*connection_0_to_1.get_protocol(), Protocol::Tcp);
            assert_eq!(*connection_1_to_0.get_protocol(), Protocol::Tcp);
        } else {
            assert_eq!(*connection_0_to_1.get_protocol(), Protocol::Utp);
            assert_eq!(*connection_1_to_0.get_protocol(), Protocol::Utp);
        }

        assert!(pub_key_0 != pub_key_1);

        // send data from 0 to 1
        {
            let data_txd = vec![0, 1, 255, 254, 222, 1];
            unwrap_result!(connection_0_to_1.send(&data_txd));

            // 1 should rx data
            let (data_rxd, peer_pub_key) = {
                let event_rxd = unwrap_result!(event_rx_1.recv());
                match event_rxd {
                    Event::NewMessage(their_pub_key, msg) => (msg , their_pub_key),
                    _ => panic!("Received unexpected event: {:?}", event_rxd),
                }
            };

            assert_eq!(data_rxd, data_txd);
            assert_eq!(peer_pub_key, pub_key_0);
        }

        // send data from 1 to 0
        {
            let data_txd = vec![10, 11, 155, 214, 202];
            unwrap_result!(connection_1_to_0.send(&data_txd));

            // 0 should rx data
            let (data_rxd, peer_pub_key) = {
                let event_rxd = unwrap_result!(event_rx_0.recv());
                match event_rxd {
                    Event::NewMessage(their_pub_key, msg) => (msg , their_pub_key),
                    _ => panic!("Received unexpected event: {:?}", event_rxd),
                }
            };

            assert_eq!(data_rxd, data_txd);
            assert_eq!(peer_pub_key, pub_key_1);
        }
    }

    #[test]
    fn start_two_services_bootstrap_communicate_exit_tcp() {
        two_services_bootstrap_communicate_and_exit(45666, true, false);
    }

    #[test]
    fn start_two_services_bootstrap_communicate_exit_udp() {
        two_services_bootstrap_communicate_and_exit(45667, false, true);
    }

    #[test]
    fn start_two_services_bootstrap_communicate_exit_tcp_and_udp() {
        two_services_bootstrap_communicate_and_exit(45668, true, true);
    }

    #[test]
    #[ignore]
    fn start_two_service_udp_rendezvous_connect() {
        let (event_sender_0, category_rx_0, event_rx_0) = get_event_sender();
        let (event_sender_1, category_rx_1, event_rx_1) = get_event_sender();

        let mut service_0 = unwrap_result!(Service::new_impl(event_sender_0, 1234, false, false));
        // let service_0 finish bootstrap - since it is the zero state, it should not find any peer
        // to bootstrap
        {
            let event_rxd = unwrap_result!(event_rx_0.recv());
            match event_rxd {
                Event::BootstrapFinished => (),
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        }

        let mut service_1 = unwrap_result!(Service::new_impl(event_sender_1, 1234, false, false));
        // let service_0 finish bootstrap - since it is the zero state, it should not find any peer
        // to bootstrap
        {
            let event_rxd = unwrap_result!(event_rx_1.recv());
            match event_rxd {
                Event::BootstrapFinished => (),
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        }

        const PREPARE_CI_TOKEN: u32 = 1234;

        service_0.prepare_connection_info(PREPARE_CI_TOKEN);
        let our_ci_0 = {
            let event_rxd = unwrap_result!(event_rx_0.recv());
            match event_rxd {
                Event::ConnectionInfoPrepared(cir) => {
                    assert_eq!(cir.result_token, PREPARE_CI_TOKEN);
                    unwrap_result!(cir.result)
                }
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        };

        service_1.prepare_connection_info(PREPARE_CI_TOKEN);
        let our_ci_1 = {
            let event_rxd = unwrap_result!(event_rx_1.recv());
            match event_rxd {
                Event::ConnectionInfoPrepared(cir) => {
                    assert_eq!(cir.result_token, PREPARE_CI_TOKEN);
                    unwrap_result!(cir.result)
                }
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        };

        let their_ci_0 = our_ci_0.to_their_connection_info();
        let their_ci_1 = our_ci_1.to_their_connection_info();

        service_0.connect(our_ci_0, their_ci_1);
        service_1.connect(our_ci_1, their_ci_0);

        let (mut connection_0_to_1, pub_key_1) = match unwrap_result!(event_rx_0.recv()) {
            Event::NewConnection { connection: Ok(connection_obj), their_pub_key } => {
                (connection_obj, their_pub_key)
            }
            m => panic!("0 Should have connected to 1. Got message {:?}", m),
        };

        let (mut connection_1_to_0, pub_key_0) = match unwrap_result!(event_rx_1.recv()) {
            Event::NewConnection { connection: Ok(connection_obj), their_pub_key } => {
                (connection_obj, their_pub_key)
            }
            m => panic!("1 Should have connected to 0. Got message {:?}", m),
        };

        // send data from 0 to 1
        {
            let data_txd = vec![0, 1, 255, 254, 222, 1];
            unwrap_result!(connection_0_to_1.send(&data_txd));

            // 1 should rx data
            let (data_rxd, peer_pub_key) = {
                let event_rxd = unwrap_result!(event_rx_1.recv());
                match event_rxd {
                    Event::NewMessage(their_pub_key,  msg) => (msg , their_pub_key),
                    _ => panic!("Received unexpected event: {:?}", event_rxd),
                }
            };

            assert_eq!(data_rxd, data_txd);
            assert_eq!(peer_pub_key, pub_key_0);
        }

        // send data from 1 to 0
        {
            let data_txd = vec![10, 11, 155, 214, 202];
            unwrap_result!(connection_1_to_0.send(&data_txd));

            // 0 should rx data
            let (data_rxd, peer_pub_key) = {
                let event_rxd = unwrap_result!(event_rx_0.recv());
                match event_rxd {
                    Event::NewMessage(their_pub_key,  msg) => (msg, their_pub_key),
                    _ => panic!("Received unexpected event: {:?}", event_rxd),
                }
            };

            assert_eq!(data_rxd, data_txd);
            assert_eq!(peer_pub_key, pub_key_1);
        }
    }
}
