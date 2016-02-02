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

use std::fmt;
use std::sync::{Arc, Mutex};
use std::hash::{Hash, SipHasher, Hasher};
use std::sync::atomic::{Ordering, AtomicBool};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
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
use ip::{IpAddr, SocketAddrExt};
use socket_addr::SocketAddr;
use event::Event;
use sodiumoxide::crypto::sign::PublicKey;
use endpoint::{Endpoint, Protocol};
use rand;
use std::fmt::{Debug, Formatter};
use net2::TcpBuilder;
use socket_utils;
use listener_message::{ListenerRequest, ListenerResponse};

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
}

impl Hash for Connection {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);
        self.our_addr.hash(state);
        self.their_addr.hash(state);
    }
}

impl Debug for Connection {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f,
               "Connection {{ protocol: {:?}, our_addr: {:?}, their_addr: {:?} }}",
               self.protocol,
               self.our_addr,
               self.their_addr)
    }
}

impl Connection {
    /// Send the `data` to a peer via this connection.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.network_tx.send(data)
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
               event_tx: ::CrustEventSender)
               -> io::Result<Connection> {
    let mut last_err = None;
    // for tcp_addr in peer_contact.tcp_acceptors {
    //     match connect_tcp_endpoint(tcp_addr,
    //                                peer_contact.pub_key,
    //                                our_contact_info.clone(),
    //                                event_tx.clone()) {
    //         Ok(connection) => return Ok(connection),
    //         Err(e) => last_err = Some(e),
    //     }
    // }

    println!("============================ 0");

    let (udp_socket, our_external_addrs) =
        try!(utp_connections::external_udp_socket(unwrap_result!(peer_contact_infos.lock())
                                                      .clone()));
    let our_secret = [255; 4];
    let connect_req = ListenerRequest::Connect {
        secret: our_secret,
        pub_key: unwrap_result!(our_contact_info.lock()).pub_key.clone(),
    };
    let serialised_connect_req = unwrap_result!(serialise(&connect_req));
    let mut read_buf = [0; 1024];

    for udp_addr in peer_contact.udp_listeners {
        println!("Trying ........ {:?}", udp_addr);
        if udp_socket.send_to(&udp_addr, &serialised_connect_req).is_err() {
            continue;
        }
        match udp_socket.recv_from(&mut read_buf) {
            Ok((bytes_rxd, peer_addr)) => {
                match deserialise::<ListenerResponse>(&read_buf[..bytes_rxd]) {
                    Ok(ListenerResponse::Connect { connect_on, secret, pub_key, }) => {
                        if secret != our_secret {
                            continue;
                        }
                        for peer_udp_hole_punched_socket_addr in connect_on {
                            match utp_connections::blocking_udp_punch_hole(cloned_udp_socket,
                                                                           Some(our_secret),
                                                                           peer_udp_hole_punched_socket_addr) {
                            Ok((our_socket, Ok(peer_addr))) => {
                                match utp_rendezvous_connect(our_socket, peer_addr, pub_key, event_tx.clone()) {
                                    Ok(connection) => return Ok(connection),
                                    Err(_) => continue,
                                }
                            }
                            Err(_) => continue,
                        }
                        }
                    }
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        }
        match connect_utp_endpoint(udp_addr,
                                   peer_contact.pub_key,
                                   our_contact_info.clone(),
                                   event_tx.clone()) {
            Ok(connection) => return Ok(connection),
            Err(e) => last_err = Some(e),
        }
    }

    println!("============================ 1");

    match last_err {
        Some(e) => Err(e),
        None => {
            Err(io::Error::new(io::ErrorKind::Other,
                               "Contact info does not contain any endpoint addresses"))
        }
    }
}

fn connect_tcp_endpoint(remote_addr: SocketAddr,
                        their_pub_key: PublicKey,
                        our_contact_info: Arc<Mutex<StaticContactInfo>>,
                        event_tx: ::CrustEventSender)
                        -> io::Result<Connection> {
    let (network_input, writer) = try!(tcp_connections::connect_tcp(remote_addr.clone()));

    let our_addr = SocketAddr(unwrap_result!(network_input.local_addr()));
    let their_addr = SocketAddr(unwrap_result!(network_input.peer_addr()));

    let network_rx = Receiver::Tcp(cbor::Decoder::from_reader(network_input));
    let joiner = RaiiThreadJoiner::new(thread!("TcpNetworkReader", move || {
        start_rx(network_rx, their_pub_key, event_tx);
    }));

    let mut connection = Connection {
        protocol: Protocol::Tcp,
        our_addr: our_addr,
        their_addr: their_addr,
        network_tx: RaiiSender(writer),
        _network_read_joiner: joiner,
    };

    let serialised_info = unwrap_result!(serialise(&*unwrap_result!(our_contact_info.lock())));
    try!(connection.send(&serialised_info[..]));

    Ok(connection)
}

fn connect_utp_endpoint(remote_addr: SocketAddr,
                        their_pub_key: PublicKey,
                        our_contact_info: Arc<Mutex<StaticContactInfo>>,
                        event_tx: ::CrustEventSender)
                        -> io::Result<Connection> {
    println!("----------------------------------- 0");
    let (network_input, writer) = try!(utp_connections::connect_utp(remote_addr.clone()));
    println!("----------------------------------- 1");
    let our_addr = SocketAddr(network_input.local_addr());
    let their_addr = SocketAddr(network_input.peer_addr());

    let network_rx = Receiver::Utp(cbor::Decoder::from_reader(network_input));
    let joiner = RaiiThreadJoiner::new(thread!("UtpNetworkReader", move || {
        start_rx(network_rx, their_pub_key, event_tx);
    }));

    Ok(Connection {
        protocol: Protocol::Utp,
        our_addr: our_addr,
        their_addr: their_addr,
        network_tx: RaiiSender(writer),
        _network_read_joiner: joiner,
    })
}

// TODO use peer_contact_infos to get the external addresses
pub fn start_tcp_accept(port: u16,
                        our_contact_info: Arc<Mutex<StaticContactInfo>>,
                        peer_contact_infos: Arc<Mutex<Vec<StaticContactInfo>>>,
                        event_tx: ::CrustEventSender)
                        -> io::Result<RaiiTcpAcceptor> {
    use std::io::Write;
    use std::io::Read;
    use std::net::ToSocketAddrs;

    let tcp_builder_listener = try!(TcpBuilder::new_v4());
    try!(socket_utils::enable_so_reuseport(try!(tcp_builder_listener.reuse_address(true))));
    let _ = try!(tcp_builder_listener.bind(("0.0.0.0", port)));

    let listener = try!(tcp_builder_listener.listen(1));
    let port = try!(listener.local_addr()).port(); // Useful if supplied port was 0

    let mut our_external_addr = None;
    let send_data = unwrap_result!(serialise(&ListenerRequest::EchoExternalAddr));
    for peer_contact in &*unwrap_result!(peer_contact_infos.lock()) {
        for tcp_acceptor_addr in &peer_contact.tcp_acceptors {
            let tcp_builder_connect = try!(TcpBuilder::new_v4());
            try!(socket_utils::enable_so_reuseport(try!(tcp_builder_connect.reuse_address(true))));
            let _ = try!(tcp_builder_connect.bind(("0.0.0.0", port)));

            match tcp_builder_connect.connect(*tcp_acceptor_addr.clone()) {
                Ok(mut stream) => {
                    match stream.write(&send_data[..]) {
                        Ok(n) => {
                            match n == send_data.len() {
                                true => (),
                                false => continue,
                            }
                        }
                        Err(_) => continue,
                    };

                    const MAX_READ_SIZE: usize = 1024;

                    let mut recv_data = [0u8; MAX_READ_SIZE];
                    let recv_size = match stream.read(&mut recv_data[..]) {
                        Ok(recv_size) => recv_size,
                        Err(_) => continue,
                    };
                    if let Ok(ListenerResponse::EchoExternalAddr { external_addr }) =
                           deserialise::<ListenerResponse>(&recv_data[..recv_size]) {
                        our_external_addr = Some(external_addr);
                        stream.shutdown(Shutdown::Both);
                        break;
                    }
                }
                Err(_) => continue,
            }
        }
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let cloned_stop_flag = stop_flag.clone();

    let mut addrs = match our_external_addr {
        Some(addr) => vec![addr],
        None => Vec::new(),
    };

    let if_addrs = try!(get_if_addrs())
                       .into_iter()
                       .map(|i| SocketAddr::new(i.addr.ip(), port))
                       .collect_vec();
    addrs.extend(if_addrs);

    // unwrap_result!(our_contact_info.lock()).tcp_acceptors.extend(addrs);

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
            let their_pub_key = their_contact_info.pub_key.clone();

            let event_tx_cloned = event_tx.clone();
            let joiner = RaiiThreadJoiner::new(thread!("TcpNetworkReader", move || {
                start_rx(network_rx, their_pub_key, event_tx_cloned);
            }));

            let connection = Connection {
                protocol: Protocol::Tcp,
                our_addr: our_addr,
                their_addr: their_addr,
                network_tx: RaiiSender(writer),
                _network_read_joiner: joiner,
            };

            let event = Event::NewConnection {
                their_pub_key: their_contact_info.pub_key,
                connection: Ok(connection),
            };

            if event_tx.send(event).is_err() {
                break;
            }
        }
    }));

    Ok(RaiiTcpAcceptor {
        port: port,
        stop_flag: stop_flag,
        _raii_joiner: joiner,
    })
}

pub fn utp_rendezvous_connect(udp_socket: UdpSocket,
                              their_addr: SocketAddr,
                              their_pub_key: PublicKey,
                              event_tx: ::CrustEventSender)
                              -> io::Result<Connection> {
    let (network_input, writer) = try!(utp_connections::rendezvous_connect_utp(udp_socket,
                                                                               their_addr));
    let our_addr = SocketAddr(network_input.local_addr());
    let their_addr = SocketAddr(network_input.peer_addr());

    let network_rx = Receiver::Utp(cbor::Decoder::from_reader(network_input));
    let joiner = RaiiThreadJoiner::new(thread!("UtpNetworkReader", move || {
        start_rx(network_rx, their_pub_key, event_tx);
    }));

    Ok(Connection {
        protocol: Protocol::Utp,
        our_addr: our_addr,
        their_addr: their_addr,
        network_tx: RaiiSender(writer),
        _network_read_joiner: joiner,
    })
}

fn start_rx(mut network_rx: Receiver, their_pub_key: PublicKey, event_tx: ::CrustEventSender) {
    while let Ok(msg) = network_rx.receive() {
        if event_tx.send(Event::NewMessage(their_pub_key, msg)).is_err() {
            break;
        }
    }
    let _ = event_tx.send(Event::LostConnection(their_pub_key));
}

mod test {
    use super::*;

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
            }
        };

        assert_eq!(hash(&connection_4), hash(&connection_4));
        assert!(hash(&connection_0) != hash(&connection_4));
    }
}
