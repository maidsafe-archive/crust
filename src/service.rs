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

use std::collections::{HashMap, HashSet};
use std::io;
use std::net;
use std::sync::{Arc, Mutex};
use service_discovery::ServiceDiscovery;
use sodiumoxide;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use nat_traversal::{MappedUdpSocket, MappingContext, PrivRendezvousInfo,
                    PubRendezvousInfo, PunchedUdpSocket, gen_rendezvous_info};


use sender_receiver::CrustMsg;
use connection::{RaiiTcpAcceptor, UtpRendezvousConnectMode};
use udp_listener::RaiiUdpListener;
use static_contact_info::StaticContactInfo;
use rand;
use config_handler::Config;
use connection::Connection;
use error::Error;
use ip::SocketAddrExt;
use connection;
use bootstrap;
use bootstrap::RaiiBootstrap;

use event::Event;
use socket_addr::SocketAddr;
use utp_connections;
use peer_id;
use peer_id::PeerId;

/// The result of a `Service::prepare_contact_info` call.
#[derive(Debug)]
pub struct ConnectionInfoResult {
    /// The token that was passed to `prepare_connection_info`.
    pub result_token: u32,
    /// The new contact info, if successful.
    pub result: io::Result<OurConnectionInfo>,
}

/// Contact info generated by a call to `Service::prepare_contact_info`.
#[derive(Debug)]
pub struct OurConnectionInfo {
    id: PeerId,
    info: PubRendezvousInfo,
    priv_info: PrivRendezvousInfo,
    // raii_tcp_acceptor: RaiiTcpAcceptor,
    // tcp_addrs: Vec<SocketAddr>,
    udp_socket: net::UdpSocket,
    static_contact_info: StaticContactInfo,
}

impl OurConnectionInfo {
    /// Convert our connection info to theirs so that we can give it to peer.
    pub fn to_their_connection_info(&self) -> TheirConnectionInfo {
        TheirConnectionInfo {
            info: self.info.clone(),
            static_contact_info: self.static_contact_info.clone(),
            // tcp_addrs: self.tcp_addrs.clone(),
            id: self.id,
        }
    }
}

/// Contact info used to connect to another peer.
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct TheirConnectionInfo {
    info: PubRendezvousInfo,
    static_contact_info: StaticContactInfo,
    // tcp_addrs: Vec<SocketAddr>,
    id: PeerId,
}

/// A structure representing a connection manager.
///
/// This abstraction has a hidden dependency on a config file. Refer to [the docs for `FileHandler`]
/// (../file_handler/struct.FileHandler.html) and [an example config file flowchart]
/// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf) for more
/// information.
pub struct Service {
    static_contact_info: Arc<Mutex<StaticContactInfo>>,
    peer_contact_infos: Arc<Mutex<Vec<StaticContactInfo>>>,
    expected_peers: Arc<Mutex<HashSet<PeerId>>>,
    service_discovery: ServiceDiscovery<StaticContactInfo>,
    event_tx: ::CrustEventSender,
    bootstrap: RaiiBootstrap,
    our_keys: (PublicKey, SecretKey),
    connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>,
    mapping_context: Arc<MappingContext>,
    tcp_acceptor_port: Option<u16>,
    utp_acceptor_port: Option<u16>,
    raii_udp_listener: Option<RaiiUdpListener>,
    raii_tcp_acceptor: Option<RaiiTcpAcceptor>,
}

impl Service {
    /// Constructs a service. User needs to create an asynchronous channel, and provide
    /// the sender half to this method. Receiver will receive all `Event`s from this library.
    pub fn new(event_tx: ::CrustEventSender,
               service_discovery_port: u16)
               -> Result<Service, Error> {
        sodiumoxide::init();

        let our_keys = box_::gen_keypair();

        // Form our initial contact info
        let static_contact_info = Arc::new(Mutex::new(StaticContactInfo {
            tcp_acceptors: Vec::new(),
            utp_custom_listeners: Vec::new(),
            mapper_servers: Vec::new(),
        }));

        let cloned_contact_info = static_contact_info.clone();
        let generator = move || unwrap_result!(cloned_contact_info.lock()).clone();
        let service_discovery = try!(ServiceDiscovery::new_with_generator(service_discovery_port,
                                                                          generator));

        let config = match ::config_handler::read_config_file() {
            Ok(cfg) => cfg,
            Err(e) => {
                debug!("Crust failed to read config file; Error: {:?};", e);
                try!(::config_handler::create_default_config_file());
                Config::make_default()
            }
        };
        let mapping_context = try!(MappingContext::new().result_discard()
                                   .or(Err(io::Error::new(io::ErrorKind::Other,
                                                          "Failed to create MappingContext"))));
        // Form initial peer contact infos - these will also contain echo-service addrs.
        let bootstrap_contacts = try!(bootstrap::get_known_contacts(&service_discovery, &config));
        for peer_contact_info in bootstrap_contacts.iter() {
            mapping_context.add_simple_servers(peer_contact_info.mapper_servers.clone());
        }
        let peer_contact_infos = Arc::new(Mutex::new(bootstrap_contacts));

        let connection_map = Arc::new(Mutex::new(HashMap::new()));

        mapping_context.add_simple_servers(config.mapper_servers);
        let mapping_context = Arc::new(mapping_context);

        let bootstrap = RaiiBootstrap::new(static_contact_info.clone(),
                                           peer_contact_infos.clone(),
                                           our_keys.0.clone(),
                                           event_tx.clone(),
                                           connection_map.clone(),
                                           mapping_context.clone());

        let service = Service {
            static_contact_info: static_contact_info,
            peer_contact_infos: peer_contact_infos,
            service_discovery: service_discovery,
            expected_peers: Arc::new(Mutex::new(HashSet::new())),
            event_tx: event_tx,
            bootstrap: bootstrap,
            our_keys: our_keys,
            connection_map: connection_map,
            mapping_context: mapping_context,
            tcp_acceptor_port: config.tcp_acceptor_port,
            utp_acceptor_port: config.utp_acceptor_port,
            raii_udp_listener: None,
            raii_tcp_acceptor: None,
        };

        Ok(service)
    }

    /// Stop the bootstraping procedure
    pub fn stop_bootstrap(&mut self) {
        self.bootstrap.stop();
    }

    /// Starts accepting TCP connections.
    pub fn start_listening_tcp(&mut self) -> io::Result<()> {
        // Start the TCP Acceptor
        self.raii_tcp_acceptor = Some(try!(connection::start_tcp_accept(self.tcp_acceptor_port
                                                                            .unwrap_or(0),
                                                   self.static_contact_info.clone(),
                                                   self.our_keys.0.clone(),
                                                   self.peer_contact_infos.clone(),
                                                   self.event_tx.clone(),
                                                   self.connection_map.clone(),
                                                   self.expected_peers.clone())));
        Ok(())
    }

    /// Starts accepting uTP connections.
    pub fn start_listening_utp(&mut self) -> io::Result<()> {
        // Start the UDP Listener
        // [TODO]: we should find the exteranl address and if we are directly acessabel here for all listerners. Also listen on ip4 and 6 for all protocols - 2016-02-10 11:28pm
        self.raii_udp_listener = Some(try!(RaiiUdpListener::new(self.utp_acceptor_port.unwrap_or(0),
                                           self.static_contact_info.clone(),
                                           self.our_keys.0.clone(),
                                           self.event_tx.clone(),
                                           self.connection_map.clone(),
                                           self.mapping_context.clone())));
        Ok(())
    }

    /// Starts listening for beacon broadcasts.
    pub fn start_service_discovery(&mut self) {
        if !self.service_discovery.set_listen_for_peers(true) {
            error!("Failed to start listening for peers.");
        }
    }

    /// Get the hole punch servers addresses of nodes that we're connected to ordered by how likely
    /// they are to be on a seperate network.
    pub fn get_ordered_helping_nodes(&self) -> Vec<SocketAddr> {
        unimplemented!()
    }

    /// Send the given `data` to the peer with the given `PeerId`.
    pub fn send(&self, id: &PeerId, data: Vec<u8>) -> io::Result<()> {
        match unwrap_result!(self.connection_map.lock())
                  .get_mut(&id)
                  .and_then(|conns| conns.get_mut(0)) {
            None => {
                let msg = format!("No connection to peer {:?}", id);
                Err(io::Error::new(io::ErrorKind::Other, msg))
            }
            Some(connection) => connection.send(CrustMsg::Message(data)),
        }
    }

    /// Disconnect from the given peer and returns whether there was a connection at all.
    pub fn disconnect(&self, id: &PeerId) -> bool {
        unwrap_result!(self.connection_map.lock()).remove(&id).is_some()
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
    /// On success `Event::NewPeer` with connected `PeerId` will
    /// be sent to the event channel. On failure, nothing is reported. Failed
    /// attempts are not notified back up to the caller. If the caller wants to
    /// know of a failed attempt, it must maintain a record of the attempt
    /// itself which times out if a corresponding
    /// `Event::NewPeer` isn't received. See also [Process for
    /// Connecting]
    /// (https://github.com/maidsafe/crust/blob/master/docs/connect.md) for
    /// details on handling of connect in different protocols.
    pub fn connect(&self,
                   our_connection_info: OurConnectionInfo,
                   their_connection_info: TheirConnectionInfo) {
        let event_tx = self.event_tx.clone();
        let connection_map = self.connection_map.clone();
        let our_public_key = self.our_keys.0.clone();
        let our_contact_info = self.static_contact_info.clone();

        unwrap_result!(self.expected_peers.lock()).insert(their_connection_info.id);

        // TODO connect to all the socket addresses of peer in parallel
        let _joiner = thread!("PeerConnectionThread", move || {
            let their_id = their_connection_info.id;

            /*
             *
             *  For now, just do utp rendezvous connect
             *
            // TODO(afck): Retry with delay, until the called connect, too.
            for tcp_addr in their_connection_info.static_contact_info.tcp_acceptors {
                match connection::connect_tcp_endpoint(tcp_addr,
                                                       our_contact_info.clone(),
                                                       our_public_key,
                                                       event_tx.clone(),
                                                       connection_map.clone(),
                                                       Some(their_id)) {
                    Err(e) => (),
                    Ok(connection) => {
                        unwrap_result!(connection_map.lock())
                            .entry(their_id)
                            .or_insert(Vec::new())
                            .push(connection);
                        let _ = event_tx.send(Event::NewPeer(Ok(()), their_id));
                        return;
                    }
                }
            };
            */

            let res = PunchedUdpSocket::punch_hole(our_connection_info.udp_socket,
                                                   our_connection_info.priv_info,
                                                   their_connection_info.info);
            let (udp_socket, public_endpoint) = match res {
                Ok(PunchedUdpSocket { socket, peer_addr }) => (socket, peer_addr),
                Err(e) => {
                    let ev = Event::NewPeer(Err(e), their_id);
                    let _ = event_tx.send(ev);
                    return;
                }
            };

            let result = match connection::utp_rendezvous_connect(udp_socket,
                                                                  public_endpoint,
                                                                  UtpRendezvousConnectMode::Normal(their_id),
                                                                  our_public_key.clone(),
                                                                  event_tx.clone(),
                                                                  connection_map.clone()) {
                Err(e) => Err(e),
                Ok(connection) => {
                    unwrap_result!(connection_map.lock())
                        .entry(their_id)
                        .or_insert(Vec::new())
                        .push(connection);
                    Ok(())
                }
            };
            let _ = event_tx.send(Event::NewPeer(result, their_id));
        });
    }

    /// Lookup a mapped udp socket based on result_token
    pub fn prepare_connection_info(&mut self, result_token: u32) {
        // FIXME: If the lsiterners are directly addressable (direct full cone or upnp mapped etc.
        // then our conact info is our static liseners
        // for udp we can map another socket, but use same local port if accessable/mapped
        // otherwise do following
        let mut peer_udp_listeners = Vec::with_capacity(100);
        for peer_contact_info in &*unwrap_result!(self.peer_contact_infos.lock()) {
            peer_udp_listeners.extend(peer_contact_info.mapper_servers.clone());
        }

        let our_static_contact_info = self.static_contact_info.clone();
        let event_tx = self.event_tx.clone();

        self.mapping_context.add_simple_servers(peer_udp_listeners);
        let result_external_socket = MappedUdpSocket::new(&self.mapping_context)
            .result_discard();
        let mapping_context = self.mapping_context.clone();
        let our_pub_key = self.our_keys.0.clone();
        let _joiner = thread!("PrepareContactInfo", move || {
            let (udp_socket, (our_priv_info, our_pub_info)) = match MappedUdpSocket::new(&mapping_context).result_discard() {
                Ok(MappedUdpSocket { socket, endpoints }) => {
                    (socket, gen_rendezvous_info(endpoints))
                }
                Err(e) => {
                    let _ = event_tx.send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                        result_token: result_token,
                        result: Err(io::Error::new(io::ErrorKind::Other,
                                                   "Cannot map UDP socket")),
                    }));
                    return;
                }
            };


            let send = Event::ConnectionInfoPrepared(ConnectionInfoResult {
                result_token: result_token,
                result: Ok(OurConnectionInfo {
                    id: peer_id::new_id(our_pub_key),
                    info: our_pub_info,
                    priv_info: our_priv_info,
                    // raii_tcp_acceptor: unimplemented!(),
                    // tcp_addrs: unimplemented!(),
                    // why are we starting a tcp acceptor?
                    // Are tcp acceptors being used to do rendezvous connections now?
                    // coz that doesn't make sense
                    udp_socket: udp_socket,
                    static_contact_info: unwrap_result!(our_static_contact_info.lock()).clone(),
                }),
            });
            let _ = event_tx.send(send);
        });
    }

    /// Returns our ID.
    pub fn id(&self) -> PeerId {
        peer_id::new_id(self.our_keys.0)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        unwrap_result!(self.connection_map.lock()).clear();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use event::Event;
    use endpoint::Protocol;

    use std::mem;
    use std::sync::mpsc;
    use std::sync::mpsc::Receiver;
    use std::thread;

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

        let mut service_0 = unwrap_result!(Service::new(event_sender_0, port));
        if use_tcp {
            unwrap_result!(service_0.start_listening_tcp());
        }
        if use_udp {
            unwrap_result!(service_0.start_listening_utp());
        }
        // let service_0 finish bootstrap - since it is the zero state, it should not find any peer
        // to bootstrap
        {
            let event_rxd = unwrap_result!(event_rx_0.recv());
            match event_rxd {
                Event::BootstrapFinished => (),
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        }
        service_0.start_service_discovery();

        let mut service_1 = unwrap_result!(Service::new(event_sender_1, port));
        if use_tcp {
            unwrap_result!(service_1.start_listening_tcp());
        }
        if use_udp {
            unwrap_result!(service_1.start_listening_utp());
        }

        // let service_1 finish bootstrap - it should bootstrap off service_0
        let id_0 = {
            let event_rxd = unwrap_result!(event_rx_1.recv());
            match event_rxd {
                Event::BootstrapConnect(their_id) => their_id,
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

        // service_0 should have received service_1's bootstrap connection by now
        let id_1 = match unwrap_result!(event_rx_0.recv()) {
            Event::BootstrapAccept(their_id) => their_id,
            _ => panic!("0 Should have got a new connection from 1."),
        };

        // TODO: Evaluate whether these are still needed.
        // if use_tcp {
        // assert_eq!(*connection_0_to_1.get_protocol(), Protocol::Tcp);
        // assert_eq!(*connection_1_to_0.get_protocol(), Protocol::Tcp);
        // } else {
        // assert_eq!(*connection_0_to_1.get_protocol(), Protocol::Utp);
        // assert_eq!(*connection_1_to_0.get_protocol(), Protocol::Utp);
        // }


        assert!(id_0 != id_1);

        // send data from 0 to 1
        {
            let data_txd = vec![0, 1, 255, 254, 222, 1];
            unwrap_result!(service_0.send(&id_1, data_txd.clone()));

            // 1 should rx data
            let (data_rxd, peer_id) = {
                let event_rxd = unwrap_result!(event_rx_1.recv());
                match event_rxd {
                    Event::NewMessage(their_id, msg) => (msg, their_id),
                    _ => panic!("Received unexpected event: {:?}", event_rxd),
                }
            };

            assert_eq!(data_rxd, data_txd);
            assert_eq!(peer_id, id_0);
        }

        // send data from 1 to 0
        {
            let data_txd = vec![10, 11, 155, 214, 202];
            unwrap_result!(service_1.send(&id_0, data_txd.clone()));

            // 0 should rx data
            let (data_rxd, peer_id) = {
                let event_rxd = unwrap_result!(event_rx_0.recv());
                match event_rxd {
                    Event::NewMessage(their_id, msg) => (msg, their_id),
                    _ => panic!("Received unexpected event: {:?}", event_rxd),
                }
            };

            assert_eq!(data_rxd, data_txd);
            assert_eq!(peer_id, id_1);
        }

        assert!(service_0.disconnect(&id_1));

        match unwrap_result!(event_rx_1.recv()) {
            Event::LostPeer(id) => assert_eq!(id, id_0),
            e => panic!("Received unexpected event: {:?}", e),
        }
    }

    #[test]
    fn start_two_services_bootstrap_communicate_exit_tcp() {
        two_services_bootstrap_communicate_and_exit(45666, true, false);
    }

    #[test]
    #[ignore] // For now, don't try to bootstrap over udp
    fn start_two_services_bootstrap_communicate_exit_udp() {
        two_services_bootstrap_communicate_and_exit(45667, false, true);
    }

    #[test]
    fn start_two_services_bootstrap_communicate_exit_tcp_and_udp() {
        two_services_bootstrap_communicate_and_exit(45668, true, true);
    }

    #[test]
    fn drop() {
        let port = 45666;
        let (event_sender_0, category_rx_0, event_rx_0) = get_event_sender();
        let (event_sender_1, category_rx_1, event_rx_1) = get_event_sender();

        let mut service_0 = unwrap_result!(Service::new(event_sender_0, port));
        unwrap_result!(service_0.start_listening_tcp());

        // Let service_0 finish bootstrap - it should not find any peer.
        match unwrap_result!(event_rx_0.recv()) {
            Event::BootstrapFinished => (),
            event_rxd => panic!("Received unexpected event: {:?}", event_rxd),
        }
        service_0.start_service_discovery();

        let mut service_1 = unwrap_result!(Service::new(event_sender_1, port));
        unwrap_result!(service_1.start_listening_tcp());

        // Let service_1 finish bootstrap - it should bootstrap off service_0.
        let id_0 = match unwrap_result!(event_rx_1.recv()) {
            Event::BootstrapConnect(their_id) => their_id,
            event => panic!("Received unexpected event: {:?}", event),
        };

        // Now service_1 should get BootstrapFinished.
        match unwrap_result!(event_rx_1.recv()) {
            Event::BootstrapFinished => (),
            event => panic!("Received unexpected event: {:?}", event),
        }

        // service_0 should have received service_1's bootstrap connection by now.
        let id_1 = match unwrap_result!(event_rx_0.recv()) {
            Event::BootstrapAccept(their_id) => their_id,
            _ => panic!("0 Should have got a new connection from 1."),
        };

        // Dropping service_0 should make service_1 receive a LostPeer event.
        mem::drop(service_0);
        match unwrap_result!(event_rx_1.recv()) {
            Event::LostPeer(id) => assert_eq!(id, id_0),
            event => panic!("Received unexpected event: {:?}", event),
        }
    }

    #[test]
    fn start_two_service_udp_rendezvous_connect() {
        let (event_sender_0, category_rx_0, event_rx_0) = get_event_sender();
        let (event_sender_1, category_rx_1, event_rx_1) = get_event_sender();

        let mut service_0 = unwrap_result!(Service::new(event_sender_0, 1234));
        // let service_0 finish bootstrap - since it is the zero state, it should not find any peer
        // to bootstrap
        {
            let event_rxd = unwrap_result!(event_rx_0.recv());
            match event_rxd {
                Event::BootstrapFinished => (),
                _ => panic!("Received unexpected event: {:?}", event_rxd),
            }
        }

        let mut service_1 = unwrap_result!(Service::new(event_sender_1, 1234));
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

        let id_1 = match unwrap_result!(event_rx_0.recv()) {
            Event::NewPeer(Ok(()), their_id) => their_id,
            m => panic!("0 Should have connected to 1. Got message {:?}", m),
        };

        let id_0 = match unwrap_result!(event_rx_1.recv()) {
            Event::NewPeer(Ok(()), their_id) => their_id,
            m => panic!("1 Should have connected to 0. Got message {:?}", m),
        };

        // send data from 0 to 1
        {
            let data_txd = vec![0, 1, 255, 254, 222, 1];
            unwrap_result!(service_0.send(&id_1, data_txd.clone()));

            // 1 should rx data
            let (data_rxd, peer_id) = {
                let event_rxd = unwrap_result!(event_rx_1.recv());
                match event_rxd {
                    Event::NewMessage(their_id, msg) => (msg, their_id),
                    _ => panic!("Received unexpected event: {:?}", event_rxd),
                }
            };

            assert_eq!(data_rxd, data_txd);
            assert_eq!(peer_id, id_0);
        }

        // send data from 1 to 0
        {
            let data_txd = vec![10, 11, 155, 214, 202];
            unwrap_result!(service_1.send(&id_0, data_txd.clone()));

            // 0 should rx data
            let (data_rxd, peer_id) = {
                let event_rxd = unwrap_result!(event_rx_0.recv());
                match event_rxd {
                    Event::NewMessage(their_id, msg) => (msg, their_id),
                    _ => panic!("Received unexpected event: {:?}", event_rxd),
                }
            };

            assert_eq!(data_rxd, data_txd);
            assert_eq!(peer_id, id_1);
        }
    }
}
