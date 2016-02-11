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

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{Ordering, AtomicBool};
use std::net::{Shutdown, TcpStream, UdpSocket};
use std::io;
use cbor;
use itertools::Itertools;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use get_if_addrs::get_if_addrs;
use static_contact_info::StaticContactInfo;
use tcp_connections;
use utp_connections;
use sender_receiver::{RaiiSender, Receiver};
use ip::SocketAddrExt;
use socket_addr::SocketAddr;
use event::Event;
use endpoint::Protocol;
use std::fmt::{Debug, Formatter};
use net2::TcpBuilder;
use socket_utils;
use listener_message::{ListenerRequest, ListenerResponse};
use peer_id;
use peer_id::PeerId;
use nat_traversal::{MappedUdpSocket, MappingContext, PrivRendezvousInfo,
                    PunchedUdpSocket, PubRendezvousInfo, gen_rendezvous_info};

/// An open connection that can be used to send messages to a peer.
///
/// Messages *from* the peer are received as Crust events, together with the peer's public key.
///
/// The connection is closed when this is dropped.
pub struct Connection {
    protocol: Protocol,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    network_tx: RaiiSender,
    _network_read_joiner: RaiiThreadJoiner,
    closed: Arc<AtomicBool>,
}

impl Hash for Connection {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);
        self.our_addr.hash(state);
        self.their_addr.hash(state);
        self.closed.load(Ordering::Relaxed).hash(state);
    }
}

impl Debug for Connection {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f,
               "Connection {{ protocol: {:?}, our_addr: {:?}, their_addr: {:?}, closed: {} }}",
               self.protocol,
               self.our_addr,
               self.their_addr,
               self.closed.load(Ordering::Relaxed))
    }
}

impl Connection {
    /// Send the `data` to a peer via this connection.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.network_tx.send(data)
    }

    /// Returns whether this connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn get_protocol(&self) -> &Protocol {
        &self.protocol
    }
}

pub struct RaiiTcpAcceptor {
    port: u16,
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
}

impl Drop for RaiiTcpAcceptor {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(&format!("127.0.0.1:{}", self.port)[..]) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

impl Debug for RaiiTcpAcceptor {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "RaiiTcpAcceptor {{ port: {}, }}", self.port)
    }
}

pub fn connect(peer_contact: StaticContactInfo,
               peer_contact_infos: Arc<Mutex<Vec<StaticContactInfo>>>,
               our_contact_info: Arc<Mutex<StaticContactInfo>>,
               event_tx: ::CrustEventSender,
               connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>,
               mc: &MappingContext)
               -> io::Result<Connection> {
    let mut last_err = None;
    for tcp_addr in peer_contact.tcp_acceptors {
        match connect_tcp_endpoint(tcp_addr,
                                   peer_id::new_id(peer_contact.pub_key),
                                   our_contact_info.clone(),
                                   event_tx.clone(),
                                   connection_map.clone()) {
            Ok(connection) => return Ok(connection),
            Err(e) => last_err = Some(e),
        }
    }

    let udp_helper_nodes: Vec<SocketAddr> = {
        let peer_contact_info = unwrap_result!(peer_contact_infos.lock());
        peer_contact_info.iter().flat_map(|ci| ci.mapper_servers.iter().cloned()).collect()
    };

    mc.add_simple_servers(udp_helper_nodes);
    let (udp_socket, (our_priv_info, our_pub_info)) = {
        match MappedUdpSocket::new(mc).result_discard() {
            Ok(MappedUdpSocket { socket, endpoints }) => {
                (socket, gen_rendezvous_info(endpoints))
            }
            Err(_) => return Err(io::Error::new(io::ErrorKind::Other,
                                                "Cannot map UDP socket")),
        }
    };

    let connect_req = ListenerRequest::Connect {
        our_info: our_pub_info.clone(),
        pub_key: unwrap_result!(our_contact_info.lock()).pub_key,
    };
    let serialised_connect_req = unwrap_result!(serialise(&connect_req));
    let mut read_buf = [0; 1024];

    for udp_addr in peer_contact.utp_custom_listeners {
        if udp_socket.send_to(&serialised_connect_req, &*udp_addr).is_err() {
            continue;
        }
        match udp_socket.recv_from(&mut read_buf) {
            Ok((bytes_rxd, _peer_addr)) => {
                match deserialise::<ListenerResponse>(&read_buf[..bytes_rxd]) {
                    Ok(ListenerResponse::Connect { our_info, their_info, pub_key, }) => {
                        if our_info != our_pub_info {
                            continue;
                        }
                        let cloned_udp_socket = try!(udp_socket.try_clone());
                        match PunchedUdpSocket::punch_hole(cloned_udp_socket,
                                                           our_priv_info.clone(),
                                                           their_info) {
                            Ok(PunchedUdpSocket { socket, peer_addr }) => {
                                match utp_rendezvous_connect(
                                    socket,
                                    peer_addr,
                                    peer_id::new_id(peer_contact.pub_key),
                                    event_tx.clone(),
                                    connection_map.clone()) {
                                    Ok(connection) => return Ok(connection),
                                    Err(_) => continue,
                                }
                            }
                            _ => continue,
                        }
                    }
                    _ => continue,
                }
            }
            Err(_) => continue,
        }
    }

    match last_err {
        Some(e) => Err(e),
        None => {
            Err(io::Error::new(io::ErrorKind::Other,
                               "Contact info does not contain any endpoint addresses"))
        }
    }
}

fn connect_tcp_endpoint(remote_addr: SocketAddr,
                        their_id: PeerId,
                        our_contact_info: Arc<Mutex<StaticContactInfo>>,
                        event_tx: ::CrustEventSender,
                        connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>)
                        -> io::Result<Connection> {
    let (network_input, writer) = try!(tcp_connections::connect_tcp(remote_addr.clone()));

    let our_addr = SocketAddr(unwrap_result!(network_input.local_addr()));
    let their_addr = SocketAddr(unwrap_result!(network_input.peer_addr()));

    let closed = Arc::new(AtomicBool::new(false));
    let closed_clone = closed.clone();
    let network_rx = Receiver::Tcp(cbor::Decoder::from_reader(network_input));
    let joiner = RaiiThreadJoiner::new(thread!("TcpNetworkReader", move || {
        start_rx(network_rx,
                 their_id,
                 event_tx,
                 closed_clone,
                 connection_map);
    }));

    let mut connection = Connection {
        protocol: Protocol::Tcp,
        our_addr: our_addr,
        their_addr: their_addr,
        network_tx: RaiiSender(writer),
        _network_read_joiner: joiner,
        closed: closed,
    };

    let serialised_info = unwrap_result!(serialise(&*unwrap_result!(our_contact_info.lock())));
    try!(connection.send(&serialised_info[..]));

    Ok(connection)
}

// fn connect_utp_endpoint(remote_addr: SocketAddr,
//                         their_pub_key: PublicKey,
//                         our_contact_info: Arc<Mutex<StaticContactInfo>>,
//                         event_tx: ::CrustEventSender,
//                         connection_map: Arc<Mutex<HashMap<PublicKey, Vec<Connection>>>>)
//                         -> io::Result<Connection> {
//     let (network_input, writer) = try!(utp_connections::connect_utp(remote_addr.clone()));
//     let our_addr = SocketAddr(network_input.local_addr());
//     let their_addr = SocketAddr(network_input.peer_addr());
//
//     let closed = Arc::new(AtomicBool::new(false));
//     let closed_clone = closed.clone();
//     let network_rx = Receiver::Utp(cbor::Decoder::from_reader(network_input));
//     let joiner = RaiiThreadJoiner::new(thread!("UtpNetworkReader", move || {
//         start_rx(network_rx,
//                  their_pub_key,
//                  event_tx,
//                  closed_clone,
//                  connection_map);
//     }));
//
//     Ok(Connection {
//         protocol: Protocol::Utp,
//         our_addr: our_addr,
//         their_addr: their_addr,
//         network_tx: RaiiSender(writer),
//         _network_read_joiner: joiner,
//         closed: closed,
//     })
// }

// TODO use peer_contact_infos to get the external addresses
pub fn start_tcp_accept(port: u16,
                        our_contact_info: Arc<Mutex<StaticContactInfo>>,
                        peer_contact_infos: Arc<Mutex<Vec<StaticContactInfo>>>,
                        event_tx: ::CrustEventSender,
                        connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>)
                        -> io::Result<RaiiTcpAcceptor> {
    use std::io::Write;
    use std::io::Read;

    let tcp_builder_listener = try!(TcpBuilder::new_v4());
    try!(socket_utils::enable_so_reuseport(try!(tcp_builder_listener.reuse_address(true))));
    let _ = try!(tcp_builder_listener.bind(("0.0.0.0", port)));

    let listener = try!(tcp_builder_listener.listen(1));
    let new_port = try!(listener.local_addr()).port(); // Useful if supplied port was 0

    // TODO: get TCP socket's external addresses (maybe using peer_contact_infos.tcp_acceptors)
    // addrs.push(external_addr); // addrs is declared below

    let stop_flag = Arc::new(AtomicBool::new(false));
    let cloned_stop_flag = stop_flag.clone();

    let mut addrs = Vec::new();

    let if_addrs = try!(get_if_addrs())
                       .into_iter()
                       .map(|i| SocketAddr::new(i.addr.ip(), new_port))
                       .collect_vec();
    addrs.extend(if_addrs);

    unwrap_result!(our_contact_info.lock()).tcp_acceptors.extend(addrs);

    let joiner = RaiiThreadJoiner::new(thread!("TcpAcceptorThread", move || {
        loop {
            let (stream, _) = match listener.accept() {
                Ok(tuple) => tuple,
                Err(err) => {
                    error!("Error in TcpListener's accept - {:?}", err);
                    break;
                }
            };

            if cloned_stop_flag.load(Ordering::SeqCst) {
                let _ = stream.shutdown(Shutdown::Both);
                break;
            }

            let (network_input, writer) = unwrap_result!(tcp_connections::upgrade_tcp(stream));

            let our_addr = SocketAddr(unwrap_result!(network_input.local_addr()));
            let their_addr = SocketAddr(unwrap_result!(network_input.peer_addr()));

            let mut network_rx = Receiver::Tcp(cbor::Decoder::from_reader(network_input));

            let their_contact_info: StaticContactInfo = {
                let raw_data = match network_rx.receive() {
                    Ok(data) => data,
                    Err(err) => {
                        error!("StaticContactInfo not shared by peer as expected. Connection \
                                will be discarded - {:?}",
                               err);
                        continue;
                    }
                };
                match deserialise(&raw_data) {
                    Ok(static_contact_info) => static_contact_info,
                    Err(err) => {
                        error!("StaticContactInfo not shared by peer as expected. Connection \
                                will be discarded - {:?}",
                               err);
                        continue;
                    }
                }
            };
			let their_id = peer_id::new_id(their_contact_info.pub_key);

            let closed = Arc::new(AtomicBool::new(false));
            let closed_clone = closed.clone();
            let event_tx_cloned = event_tx.clone();
            let connection_map_clone = connection_map.clone();
            let joiner = RaiiThreadJoiner::new(thread!("TcpNetworkReader", move || {
                start_rx(network_rx,
                         their_id,
                         event_tx_cloned,
                         closed_clone,
                         connection_map_clone);
            }));

            let connection = Connection {
                protocol: Protocol::Tcp,
                our_addr: our_addr,
                their_addr: their_addr,
                network_tx: RaiiSender(writer),
                _network_read_joiner: joiner,
                closed: closed,
            };

            unwrap_result!(connection_map.lock())
                .entry(their_id)
                .or_insert(Vec::new())
                .push(connection);
            let event = Event::NewPeer(Ok(()), their_id);

            if event_tx.send(event).is_err() {
                break;
            }
        }
    }));

    Ok(RaiiTcpAcceptor {
        port: new_port,
        stop_flag: stop_flag,
        _raii_joiner: joiner,
    })
}

pub fn utp_rendezvous_connect(udp_socket: UdpSocket,
                              their_addr: SocketAddr,
                              their_id: PeerId,
                              event_tx: ::CrustEventSender,
                              connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>)
                              -> io::Result<Connection> {
    let (network_input, writer) = try!(utp_connections::rendezvous_connect_utp(udp_socket,
                                                                               their_addr));
    let our_addr = SocketAddr(network_input.local_addr());
    let their_new_addr = SocketAddr(network_input.peer_addr());

    let closed = Arc::new(AtomicBool::new(false));
    let closed_clone = closed.clone();
    let network_rx = Receiver::Utp(cbor::Decoder::from_reader(network_input));
    let joiner = RaiiThreadJoiner::new(thread!("UtpNetworkReader", move || {
        start_rx(network_rx,
                 their_id,
                 event_tx,
                 closed_clone,
                 connection_map);
    }));

    Ok(Connection {
        protocol: Protocol::Utp,
        our_addr: our_addr,
        their_addr: their_new_addr,
        network_tx: RaiiSender(writer),
        _network_read_joiner: joiner,
        closed: closed,
    })
}

fn start_rx(mut network_rx: Receiver,
            their_id: PeerId,
            event_tx: ::CrustEventSender,
            closed: Arc<AtomicBool>,
            connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>) {
    while let Ok(msg) = network_rx.receive() {
        if event_tx.send(Event::NewMessage(their_id, msg)).is_err() {
            break;
        }
    }
    closed.store(true, Ordering::Relaxed);
    // Drop the connection in a separate thread, because the destructor joins _this_ thread.
    let _ = thread!("ConnectionDropper", move || {
        let mut lock = unwrap_result!(connection_map.lock());
        if let Entry::Occupied(mut entry) = lock.entry(their_id) {
            entry.get_mut().retain(|connection| !connection.is_closed());
            if entry.get().is_empty() {
                let _ = entry.remove();
                let _ = event_tx.send(Event::LostPeer(their_id));
            }
        }
    });
}

mod test {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{Ordering, AtomicBool};
    use std::sync::mpsc;
    use std::str::FromStr;
    use std::hash::{Hash, SipHasher, Hasher};
    use std::net;

    use sender_receiver::RaiiSender;
    use maidsafe_utilities::thread::RaiiThreadJoiner;

    use endpoint::Protocol;
    use socket_addr::SocketAddr;

    /// Hash `object_to_hash` using a `SipHasher`
    fn hash<T: Hash>(object_to_hash: &T) -> u64 {
        let mut sip_hasher = SipHasher::new();
        object_to_hash.hash(&mut sip_hasher);
        sip_hasher.finish()
    }

    #[test]
    fn connection_hash() {
        let connection_0 = {
            let (tx, _) = mpsc::channel();
            let raii_joiner = RaiiThreadJoiner::new(thread!("DummyThread", move || ()));

            Connection {
                protocol: Protocol::Tcp,
                our_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("10.199.254.200:\
                                                                               30000"))),
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.254.200:\
                                                                                 30000"))),
                network_tx: RaiiSender(tx),
                _network_read_joiner: raii_joiner,
                closed: Arc::new(AtomicBool::new(false)),
            }
        };

        // Same as connection_0
        let connection_1 = {
            let (tx, _) = mpsc::channel();
            let raii_joiner = RaiiThreadJoiner::new(thread!("DummyThread", move || ()));

            Connection {
                protocol: Protocol::Tcp,
                our_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("10.199.254.200:\
                                                                               30000"))),
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.254.200:\
                                                                                 30000"))),
                network_tx: RaiiSender(tx),
                _network_read_joiner: raii_joiner,
                closed: Arc::new(AtomicBool::new(false)),
            }
        };

        assert_eq!(hash(&connection_0), hash(&connection_0));
        assert_eq!(hash(&connection_0), hash(&connection_1));

        // Protocol different
        let connection_2 = {
            let (tx, _) = mpsc::channel();
            let raii_joiner = RaiiThreadJoiner::new(thread!("DummyThread", move || ()));

            Connection {
                protocol: Protocol::Utp,
                our_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("10.199.254.200:\
                                                                               30000"))),
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.254.200:\
                                                                                 30000"))),
                network_tx: RaiiSender(tx),
                _network_read_joiner: raii_joiner,
                closed: Arc::new(AtomicBool::new(false)),
            }
        };

        assert_eq!(hash(&connection_2), hash(&connection_2));
        assert!(hash(&connection_0) != hash(&connection_2));

        // our_addr different
        let connection_3 = {
            let (tx, _) = mpsc::channel();
            let raii_joiner = RaiiThreadJoiner::new(thread!("DummyThread", move || ()));

            Connection {
                protocol: Protocol::Tcp,
                our_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("10.199.254.201:\
                                                                               30000"))),
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.254.200:\
                                                                                 30000"))),
                network_tx: RaiiSender(tx),
                _network_read_joiner: raii_joiner,
                closed: Arc::new(AtomicBool::new(false)),
            }
        };

        assert_eq!(hash(&connection_3), hash(&connection_3));
        assert!(hash(&connection_0) != hash(&connection_3));

        // their_addr different
        let connection_4 = {
            let (tx, _) = mpsc::channel();
            let raii_joiner = RaiiThreadJoiner::new(thread!("DummyThread", move || ()));

            Connection {
                protocol: Protocol::Tcp,
                our_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("10.199.254.200:\
                                                                               30000"))),
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.253.200:\
                                                                                 30000"))),
                network_tx: RaiiSender(tx),
                _network_read_joiner: raii_joiner,
                closed: Arc::new(AtomicBool::new(false)),
            }
        };

        assert_eq!(hash(&connection_4), hash(&connection_4));
        assert!(hash(&connection_0) != hash(&connection_4));

        // closed different
        let connection_5 = {
            let (tx, _) = mpsc::channel();
            let raii_joiner = RaiiThreadJoiner::new(thread!("DummyThread", move || ()));

            Connection {
                protocol: Protocol::Tcp,
                our_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("10.199.254.200:\
                                                                               30000"))),
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.254.200:\
                                                                                 30000"))),
                network_tx: RaiiSender(tx),
                _network_read_joiner: raii_joiner,
                closed: Arc::new(AtomicBool::new(true)),
            }
        };

        assert_eq!(hash(&connection_5), hash(&connection_5));
        assert!(hash(&connection_0) != hash(&connection_5));
    }
}
