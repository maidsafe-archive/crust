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

use transport::{Sender, Receiver};
use std::io;
use ip::{IpAddr, SocketAddrExt};
use socket_addr::SocketAddr;
use event::Event;
use sodiumoxide::crypto::sign::PublicKey;

pub struct Connection {
    protocol: Protocol,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    network_tx: Sender, /* _writer_joiner: RaiiThreadJoiner,
                         * _reader_joiner: RaiiThreadJoiner, */
}

impl Connection {
    // // FIXME: There needs to be a way to break from this blocking command.
    // pub fn connect(remote_ep: Endpoint) -> IoResult<Transport> {
    //     match *remote_ep.protocol() {
    //         Protocol::Tcp => {
    //             let (i, o) = try!(tcp_connections::connect_tcp(remote_ep.socket_addr().clone())
    //                                   .map_err(|e| {
    //                                       io::Error::new(io::ErrorKind::NotConnected,
    //                                                      e.description())
    //                                   }));
    //             let connection_id = Connection::new(Protocol::Tcp,
    //                                                 SocketAddr(try!(i.local_addr())),
    //                                                 SocketAddr(try!(i.peer_addr())));

    //             Ok(Transport {
    //                 receiver: sender_receiver::Receiver::Tcp(cbor::Decoder::from_reader(i)),
    //                 sender: sender_receiver::Sender::Tcp(o),
    //                 connection_id: connection_id,
    //             })
    //         }
    //         Protocol::Utp => {
    //             let (i, o) = try!(utp_connections::connect_utp(remote_ep.socket_addr().clone())
    //                                   .map_err(|e| {
    //                                       io::Error::new(io::ErrorKind::NotConnected,
    //                                                      e.description())
    //                                   }));

    //             let connection_id = Connection::new(Protocol::Utp,
    //                                                 SocketAddr(i.local_addr()),
    //                                                 SocketAddr(i.peer_addr()));

    //             Ok(Transport {
    //                 receiver: sender_receiver::Receiver::Utp(cbor::Decoder::from_reader(i)),
    //                 sender: sender_receiver::Sender::Utp(o),
    //                 connection_id: connection_id,
    //             })
    //         }
    //     }
    // }

    pub fn udp_rendezvous_connect(udp_socket: UdpSocket,
                                  their_addr: SocketAddr,
                                  pub_key: PublicKey)
                                  -> io::Result<Self> {
        let (network_input, writer) = try!(utp_connections::rendezvous_connect_utp(udp_socket,
                                                                                   their_addr));
        let our_addr = SocketAddr(network_input.local_addr());
        let their_addr = SocketAddr(network_input.peer_addr());

        let network_rx = Receiver::Utp(cbor::Decoder::from_reader(network_input));
        let joiner = RaiiThreadJoiner::new(thread!("NetworkReader", move || {
            Connection::start_rx(network_rx, their_pub_key, event_tx);
        }));

        Connection {
            protocol: Protocol::Utp,
            our_addr: our_addr,
            their_addr: their_addr,
            network_tx: Sender::Utp(writer),
            _network_read_joiner: joiner,
        }
    }

    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        try!(self.network_tx.send(data))
    }

    fn start_rx(network_rx: Receiver, their_pub_key: PublicKey, event_tx: ::CrustEventSender) {
        while let Ok(msg) = receiver.receive() {
            if event_sender.send(Event::NewMessage(their_pub_key, msg)).is_err() {
                break;
            }
        }
        let _ = event_tx.send(Event::LostConnection(their_pub_key));
    }
}

// TODO see how to gracefully exit threads
// impl Drop for Connection {
//     fn drop(&mut self) {
//         let _ = self.tx.send(WriterEvent::Terminate);
//     }
// }

// enum WriterEvent {
//     SendMsg(Vec<u8>),
//     Terminate,
// }

// pub struct ConnectionData {
//     pub message_sender: transport::Sender,
//     pub mapper_address: Option<SocketAddr>,
//     pub mapper_external_address: Option<SocketAddr>, // pub reader_thread: RaiiThreadJoiner,
// }
//
// pub struct ConnectionMap {
//     inner: Arc<Mutex<ConnectionMapInner>>,
// }
//
// struct ConnectionMapInner {
//     connections: HashMap<Connection, ConnectionData>,
//     event_sender: ::CrustEventSender,
// }
//
// impl Drop for ConnectionMap {
//     fn drop(&mut self) {
//         let mut inner = unwrap_result!(self.inner.lock());
//         let connections: Vec<Connection> = inner.connections.keys().cloned().collect();
//         for c in connections {
//             inner.unregister_connection(c);
//         }
//     }
// }

// impl ConnectionMap {
//     pub fn new(event_sender: ::CrustEventSender) -> ConnectionMap {
//         ConnectionMap { inner: Arc::new(Mutex::new(ConnectionMapInner::new(event_sender))) }
//     }
//
//     pub fn get_ordered_helping_nodes(&self) -> Vec<SocketAddr> {
//         let inner = unwrap_result!(self.inner.lock());
//         inner.get_ordered_helping_nodes()
//     }
//
//     pub fn is_connected_to(&self, endpoint: &Endpoint) -> bool {
//         let inner = unwrap_result!(self.inner.lock());
//         inner.is_connected_to(endpoint)
//     }
//
//     // pub fn get(&self, connection: &Connection) -> Option<ConnectionData> {
//     // let inner = unwrap_result!(self.inner.lock());
//     // inner.get(connection)
//     // }
//     //
//
//     pub fn send(&self, connection: Connection, bytes: Vec<u8>) {
//         let mut inner = unwrap_result!(self.inner.lock());
//         inner.send(connection, bytes)
//     }
//
//     pub fn register_connection(&self,
//                                handshake: Handshake,
//                                transport: Transport)
//                                -> io::Result<Connection> {
//         let me = self.inner.clone();
//         let mut inner = unwrap_result!(self.inner.lock());
//         inner.register_connection(handshake, transport, me)
//     }
//
//     pub fn unregister_connection(&self, connection: Connection) {
//         let mut inner = unwrap_result!(self.inner.lock());
//         inner.unregister_connection(connection)
//     }
// }

// impl ConnectionMapInner {
//     pub fn new(event_sender: ::CrustEventSender) -> ConnectionMapInner {
//         ConnectionMapInner {
//             connections: HashMap::new(),
//             event_sender: event_sender,
//         }
//     }
//
//     pub fn get_ordered_helping_nodes(&self) -> Vec<SocketAddr> {
//         let mut addrs = self.connections
//                             .iter()
//                             .filter_map(|pair| pair.1.mapper_address.clone())
//                             .collect::<Vec<_>>();
//
//         addrs.sort_by(|addr1, addr2| {
//             ::util::heuristic_geo_cmp(&SocketAddrExt::ip(&**addr1), &SocketAddrExt::ip(&**addr2))
//                 .reverse()
//         });
//
//         addrs
//     }
//
//     pub fn is_connected_to(&self, endpoint: &Endpoint) -> bool {
//         for connection in self.connections.keys() {
//             if connection.peer_endpoint() == *endpoint {
//                 return true;
//             }
//         }
//         false
//     }

// pub fn get(&self, connection: &Connection) -> Option<ConnectionData> {
// self.connections.get(connection).map(|c| c.clone())
// }
//

//    pub fn send(&mut self, connection: Connection, bytes: Vec<u8>) {
//        let dropped = match self.connections.get_mut(&connection) {
//            Some(mut connection_data) => {
//                let writer = &mut connection_data.message_sender;
//                if let Err(_what) = writer.send(&Message::UserBlob(bytes)) {
//                    true
//                } else {
//                    false
//                }
//            }
//            None => {
//                // Connection already destroyed or never existed.
//                false
//            }
//        };
//        if dropped {
//            self.unregister_connection(connection);
//        };
//    }

//    pub fn register_connection(&mut self,
//                               handshake: Handshake,
//                               transport: Transport,
//                               me: Arc<Mutex<ConnectionMapInner>>)
//                               -> io::Result<Connection> {
//        let connection_id = transport.connection_id.clone();
//        let mut receiver = transport.receiver;
//        let sender = transport.sender;
//
//        debug_assert!(!self.connections.contains_key(&connection_id));
//
//        let mapper_addr = match handshake.mapper_port {
//            Some(port) => {
//                let peer_addr = connection_id.peer_endpoint()
//                                             .ip();
//                match peer_addr {
//                    IpAddr::V4(a) => {
//                        Some(SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(a, port))))
//                    }
//                    // FIXME(dirvine) Handle ip6 :10/01/2016
//                    IpAddr::V6(_) => unimplemented!(),
//                }
//            }
//            None => None,
//        };
//
//        let connection_id_mv = connection_id.clone();
//        // start the reading thread
//        let event_sender = self.event_sender.clone();
//        // let reader_thread = RaiiThreadJoiner::new(thread!("reader", move || {
//        // TODO (canndrew): We risk leaking this thread if we don't keep a handle to it.
//        let _ = thread!("reader", move || {
//            while let Ok(msg) = receiver.receive() {
//                match msg {
//                    Message::UserBlob(msg) => {
//                        if event_sender.send(Event::NewMessage(connection_id_mv.clone(), msg))
//                                       .is_err() {
//                            break;
//                        }
//                    }
//                    Message::HolePunchAddress(a) => {
//                        let connection = connection_id_mv.clone();
//                        let mut inner = unwrap_result!(me.lock());
//                        if let Some(cd) = inner.connections.get_mut(&connection) {
//                            cd.mapper_external_address = Some(a);
//                        }
//                    }
//                }
//            }
//            let mut inner = unwrap_result!(me.lock());
//            inner.unregister_connection(connection_id_mv);
//        });
//        let connection_data = ConnectionData {
//            message_sender: sender,
//            mapper_address: mapper_addr,
//            mapper_external_address: handshake.external_addr, // reader_thread: reader_thread,
//        };
//        let _ = self.connections.insert(connection_id.clone(), connection_data);
//
//        Ok(connection_id)
//    }

//    pub fn unregister_connection(&mut self, connection: Connection) {
//        // Avoid sending duplicate LostConnection event.
//        if self.connections.remove(&connection).is_none() {
//            return;
//        }
//
//        let _ = self.event_sender.send(Event::LostConnection(connection));
//    }
// }
