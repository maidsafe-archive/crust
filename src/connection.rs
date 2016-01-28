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
use std::sync::atomic::{Ordering, AtomicBool};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::io;
use cbor;
use itertools::Itertools;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use get_if_addrs::get_if_addrs;
use contact_info::{ContactInfo, ContactInfoHandle};
use tcp_connections;
use utp_connections;
use sender_receiver::{Sender, Receiver};
use ip::{IpAddr, SocketAddrExt};
use socket_addr::SocketAddr;
use event::Event;
use sodiumoxide::crypto::sign::PublicKey;
use endpoint::{Endpoint, Protocol};

/// An open connection that can be used to send messages to a peer.
///
/// Messages *from* the peer are received as Crust events, together with the peer's public key.
///
/// The connection is closed when this is dropped.
pub struct Connection {
    protocol: Protocol,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    network_tx: Sender,
    // _network_write_joiner: RaiiThreadJoiner,
    _network_read_joiner: RaiiThreadJoiner,
}

impl Connection {
    /// Send the `data` to a peer via this connection.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.network_tx.send(data.clone())
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "Connection {{ protocol: {:?}, our_addr: {:?}, their_addr: {:?} }}",
               self.protocol,
               self.our_addr,
               self.their_addr)
    }
}

// TODO see how to gracefully exit threads
// impl Drop for Connection {
//     fn drop(&mut self) {
//         let _ = self.network_tx.send(WriterEvent::Terminate);
//     }
// }

pub struct RaiiTcpAcceptor {
    port: u16,
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
}

impl Drop for RaiiTcpAcceptor {
    fn drop(&mut self) {
        self.stop_flag.store(false, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(&format!("127.0.0.1:{}", self.port)[..]) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

pub fn connect(contact: ContactInfo,
               our_contact_info: ContactInfoHandle,
               event_tx: ::CrustEventSender)
               -> io::Result<Connection> {
    let mut last_err = None;
    for tcp_addr in contact.tcp_acceptors {
        match connect_tcp_endpoint(tcp_addr, contact.pub_key, our_contact_info, event_tx) {
            Ok(connection) => return Ok(connection),
            Err(e) => last_err = Some(e),
        }
    }

    for udp_addr in contact.udp_listeners {
        match connect_utp_endpoint(udp_addr, contact.pub_key, our_contact_info, event_tx) {
            Ok(connection) => return Ok(connection),
            Err(e) => last_err = Some(e),
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
                        their_pub_key: PublicKey,
                        our_contact_info: ContactInfoHandle,
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
        network_tx: Sender::Tcp(writer),
        _network_read_joiner: joiner,
    };

    let serialised_info = unwrap_result!(serialise(&*unwrap_result!(our_contact_info.lock())));
    try!(connection.send(&serialised_info[..]));

    Ok(connection)
}

fn connect_utp_endpoint(remote_addr: SocketAddr,
                        their_pub_key: PublicKey,
                        our_contact_info: ContactInfoHandle,
                        event_tx: ::CrustEventSender)
                        -> io::Result<Connection> {
    let (network_input, writer) = try!(utp_connections::connect_utp(remote_addr.clone()));
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
        network_tx: Sender::Utp(writer),
        _network_read_joiner: joiner,
    })
}

pub fn start_tcp_accept(port: u16,
                        our_contact_info: ContactInfoHandle,
                        event_tx: ::CrustEventSender)
                        -> io::Result<RaiiTcpAcceptor> {
    let listener = try!(TcpListener::bind(("0.0.0.0", port)));
    let port = try!(listener.local_addr()).port(); // Useful if supplied port was 0

    let stop_flag = Arc::new(AtomicBool::new(false));
    let cloned_stop_flag = stop_flag.clone();

    let if_addrs = try!(get_if_addrs())
                       .into_iter()
                       .map(|i| SocketAddr::new(i.addr.ip(), port))
                       .collect_vec();

    unwrap_result!(our_contact_info.lock()).tcp_acceptors.extend(if_addrs);
    let event_tx_to_acceptor = event_tx.clone();

    let joiner = RaiiThreadJoiner::new(thread!("TcpAcceptorThread", move || {
        for stream in listener.incoming().filter_map(Result::ok) {
            if cloned_stop_flag.load(Ordering::SeqCst) {
                let _ = stream.shutdown(Shutdown::Both);
                break;
            }

            let (network_input, writer) = unwrap_result!(tcp_connections::upgrade_tcp(stream));

            let our_addr = SocketAddr(unwrap_result!(network_input.local_addr()));
            let their_addr = SocketAddr(unwrap_result!(network_input.peer_addr()));

            let mut network_rx = Receiver::Tcp(cbor::Decoder::from_reader(network_input));

            let their_contact_info: ContactInfo =
                unwrap_result!(deserialise(&unwrap_result!(network_rx.receive())[..]));
            let their_pub_key = their_contact_info.pub_key.clone();

            let event_tx_to_reader = event_tx.clone();
            let joiner = RaiiThreadJoiner::new(thread!("TcpNetworkReader", move || {
                start_rx(network_rx, their_pub_key, event_tx_to_reader);
            }));

            let connection = Connection {
                protocol: Protocol::Tcp,
                our_addr: our_addr,
                their_addr: their_addr,
                network_tx: Sender::Tcp(writer),
                _network_read_joiner: joiner,
            };

            let event = Event::NewConnection {
                their_pub_key: their_contact_info.pub_key,
                connection: Ok(connection),
            };

            if event_tx_to_acceptor.send(event).is_err() {
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

pub fn udp_rendezvous_connect(udp_socket: UdpSocket,
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
        network_tx: Sender::Utp(writer),
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
