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
use std::sync::atomic::AtomicBool;
use std::net::{Shutdown, TcpListener, UdpSocket};
use std::sync::atomic::Ordering;
use std::io;
use cbor;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use get_if_addrs::get_if_addrs;
use acceptor::TcpAcceptor;
use contact_info::ContactInfo;
use tcp_connections;
use utp_connections;
use sender_receiver::{Sender, Receiver};
use ip::{IpAddr, SocketAddrExt};
use socket_addr::SocketAddr;
use event::Event;
use sodiumoxide::crypto::sign::PublicKey;
use endpoint::{Endpoint, Protocol};

pub struct Connection {
    protocol: Protocol,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    network_tx: Sender,
    // _network_write_joiner: RaiiThreadJoiner,
    _network_read_joiner: RaiiThreadJoiner,
}

impl Connection {
    pub fn connect(remote_ep: Endpoint,
                   their_pub_key: PublicKey,
                   our_contact_info: Arc<Mutex<ContactInfo>>,
                   event_tx: ::CrustEventSender)
                   -> io::Result<Connection> {
        match *remote_ep.protocol() {
            Protocol::Tcp => {
                let (network_input, writer) =
                    try!(tcp_connections::connect_tcp(remote_ep.socket_addr().clone()));

                let our_addr = SocketAddr(unwrap_result!(network_input.local_addr()));
                let their_addr = SocketAddr(unwrap_result!(network_input.peer_addr()));

                let network_rx = Receiver::Tcp(cbor::Decoder::from_reader(network_input));
                let joiner = RaiiThreadJoiner::new(thread!("TcpNetworkReader", move || {
                    Connection::start_rx(network_rx, their_pub_key, event_tx);
                }));

                let connection = Connection {
                    protocol: Protocol::Tcp,
                    our_addr: our_addr,
                    their_addr: their_addr,
                    network_tx: Sender::Tcp(writer),
                    _network_read_joiner: joiner,
                };

                let serialised_info =
                    unwrap_result!(serialise(&*unwrap_result!(our_contact_info.lock())));
                try!(connection.send(&serialised_info[..]));

                Ok(connection)
            }
            Protocol::Utp => {
                let (network_input, writer) =
                    try!(utp_connections::connect_utp(remote_ep.socket_addr().clone()));
                let our_addr = SocketAddr(network_input.local_addr());
                let their_addr = SocketAddr(network_input.peer_addr());

                let network_rx = Receiver::Utp(cbor::Decoder::from_reader(network_input));
                let joiner = RaiiThreadJoiner::new(thread!("UtpNetworkReader", move || {
                    Connection::start_rx(network_rx, their_pub_key, event_tx);
                }));

                Ok(Connection {
                    protocol: Protocol::Utp,
                    our_addr: our_addr,
                    their_addr: their_addr,
                    network_tx: Sender::Utp(writer),
                    _network_read_joiner: joiner,
                })
            }
        }
    }

    pub fn start_tcp_accept(port: u16,
                            our_contact_info: Arc<Mutex<ContactInfo>>,
                            event_tx: ::CrustEventSender)
                            -> io::Result<TcpAcceptor> {
        let listener = try!(TcpListener::bind(("0.0.0.0", port)));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let cloned_stop_flag = stop_flag.clone();

        let if_addrs = try!(get_if_addrs())
                           .into_iter()
                           .filter(|i| !i.is_loopback())
                           .map(|addr| SocketAddr::new(addr.ip(), port))
                           .collect();

        unwrap_result!(our_contact_info.lock()).tcp_acceptors.extend(if_addrs);

        let joiner = RaiiThreadJoiner::new(thread!("TcpAcceptorThread", move || {
            loop {
                let (stream, _remote_endpoint) = unwrap_result!(listener.accept());

                if cloned_stop_flag.load(Ordering::SeqCst) {
                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }

                let (network_input, writer) = unwrap_result!(tcp_connections::upgrade_tcp(stream));

                let our_addr = SocketAddr(unwrap_result!(network_input.local_addr()));
                let their_addr = SocketAddr(unwrap_result!(network_input.peer_addr()));

                let network_rx = Receiver::Tcp(cbor::Decoder::from_reader(network_input));

                let their_contact_info: ContactInfo =
                    unwrap_result!(deserialise(&unwrap_result!(network_rx.receive())[..]));
                let their_pub_key = their_contact_info.pub_key.clone();

                let joiner = RaiiThreadJoiner::new(thread!("TcpNetworkReader", move || {
                    Connection::start_rx(network_rx, their_pub_key, event_tx);
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

                if event_tx.send(event).is_err() {
                    break;
                }
            }
        }));

        Ok(TcpAcceptor {
            port: port,
            stop_flag: stop_flag,
            _raii_joiner: joiner,
        })
    }

    pub fn udp_rendezvous_connect(udp_socket: UdpSocket,
                                  their_addr: SocketAddr,
                                  their_pub_key: PublicKey,
                                  event_tx: ::CrustEventSender)
                                  -> io::Result<Self> {
        let (network_input, writer) = try!(utp_connections::rendezvous_connect_utp(udp_socket,
                                                                                   their_addr));
        let our_addr = SocketAddr(network_input.local_addr());
        let their_addr = SocketAddr(network_input.peer_addr());

        let network_rx = Receiver::Utp(cbor::Decoder::from_reader(network_input));
        let joiner = RaiiThreadJoiner::new(thread!("UtpNetworkReader", move || {
            Connection::start_rx(network_rx, their_pub_key, event_tx);
        }));

        Ok(Connection {
            protocol: Protocol::Utp,
            our_addr: our_addr,
            their_addr: their_addr,
            network_tx: Sender::Utp(writer),
            _network_read_joiner: joiner,
        })
    }

    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        self.network_tx.send(data)
    }

    fn start_rx(network_rx: Receiver, their_pub_key: PublicKey, event_tx: ::CrustEventSender) {
        while let Ok(msg) = network_rx.receive() {
            if event_tx.send(Event::NewMessage(their_pub_key, msg)).is_err() {
                break;
            }
        }
        let _ = event_tx.send(Event::LostConnection(their_pub_key));
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Connection {{ protocol: {:?}, our_addr: {:?}, their_addr: {:?} }}",
               self.protocol, self.our_addr, self.their_addr)
    }
}

// TODO see how to gracefully exit threads
// impl Drop for Connection {
//     fn drop(&mut self) {
//         let _ = self.tx.send(WriterEvent::Terminate);
//     }
// }
