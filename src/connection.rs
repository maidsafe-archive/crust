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
use std::collections::hash_map::Entry;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{Ordering, AtomicBool};
use std::net::{Shutdown, TcpStream, Ipv4Addr, SocketAddrV4};
use std::net;
use std::io;
use std::time::Duration;

use rand;
use maidsafe_utilities::event_sender::{EventSenderError, MaidSafeEventCategory};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use static_contact_info::StaticContactInfo;
use tcp_connections;
use sender_receiver::{RaiiSender, Receiver, CrustMsg};
use socket_addr::SocketAddr;
use event::{Event, WriteEvent};
use endpoint::Protocol;
use std::fmt::{Debug, Formatter};
use peer_id;
use peer_id::PeerId;
use bootstrap_handler::BootstrapHandler;
use nat_traversal::MappingContext;
use nat_traversal;
use sodiumoxide::crypto::box_::PublicKey;

type CrustEventSenderError = EventSenderError<MaidSafeEventCategory, Event>;

#[derive(Debug, Clone, Copy)]
pub enum EstablishmentMethod {
    Direct(u32),
    Rendezvous,
}

/// An open connection that can be used to send messages to a peer.
///
/// Messages *from* the peer are received as Crust events, together with the peer's public key.
///
/// The connection is closed when this is dropped.
pub struct Connection {
    protocol: Protocol,
    our_addr: SocketAddr,
    their_addr: SocketAddr,
    establishment_method: EstablishmentMethod,
    network_tx: RaiiSender,
    _network_read_joiner: RaiiThreadJoiner,
    closed: Arc<AtomicBool>,
}

/// Information about a `Connection`
pub struct ConnectionInfo {
    pub protocol: Protocol,
    pub our_addr: SocketAddr,
    pub their_addr: SocketAddr,
    pub establishment_method: EstablishmentMethod,
    pub closed: bool,
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
        f.debug_struct("Connection")
         .field("our_addr", &self.our_addr)
         .field("their_addr", &self.their_addr)
         .field("establishment_method", &self.establishment_method)
         .field("closed", &self.closed.load(Ordering::Relaxed))
         .finish()
    }
}

impl Connection {
    /// Get a `ConnectionInfo` that describes this connection.
    pub fn get_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            protocol: self.protocol,
            our_addr: self.our_addr,
            their_addr: self.their_addr,
            establishment_method: self.establishment_method,
            closed: self.closed.load(Ordering::Relaxed),
        }
    }

    /// Send the `data` to a peer via this connection.
    pub fn send(&mut self, msg: CrustMsg) -> io::Result<()> {
        self.network_tx.send(msg)
    }

    /// Returns whether this connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
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
               heart_beat_timeout: Duration,
               inactivity_timeout: Duration,
               our_public_key: PublicKey,
               event_tx: ::CrustEventSender,
               connection_map: Arc<Mutex<HashMap<PeerId, Connection>>>,
               bootstrap_cache: Arc<Mutex<BootstrapHandler>>,
               mc: &MappingContext,
               version_hash: u64)
               -> io::Result<()> {
    let static_contact_info = peer_contact.clone();

    mc.add_simple_tcp_servers(static_contact_info.tcp_mapper_servers.iter().cloned());

    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "No TCP acceptors found.");
    for tcp_addr in peer_contact.tcp_acceptors {
        match connect_tcp_endpoint(tcp_addr,
                                   heart_beat_timeout,
                                   inactivity_timeout,
                                   our_public_key,
                                   event_tx.clone(),
                                   connection_map.clone(),
                                   None,
                                   None,
                                   version_hash) {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!("TCP direct connect failed: {}", e);
                last_err = e;
            }
        }
    }

    match unwrap_result!(bootstrap_cache.lock())
              .update_contacts(vec![], vec![static_contact_info]) {
        Ok(()) => (),
        Err(e) => {
            warn!("Unable to update bootstrap cache: {}", e);
        }
    };
    Err(last_err)
}

pub fn tcp_rendezvous_connect(connection_map: Arc<Mutex<HashMap<PeerId, Connection>>>,
                              heart_beat_timeout: Duration,
                              inactivity_timeout: Duration,
                              event_tx: ::CrustEventSender,
                              tcp_stream: TcpStream,
                              their_id: PeerId)
                              -> io::Result<()> {
    let (network_input, writer) = try!(tcp_connections::upgrade_tcp(tcp_stream,
                                                                    heart_beat_timeout,
                                                                    inactivity_timeout));
    let our_addr = SocketAddr(try!(network_input.local_addr()));
    let their_addr = SocketAddr(try!(network_input.peer_addr()));
    let network_rx = Receiver::tcp(network_input);
    let network_tx = RaiiSender(writer);

    let mut cm = connection_map.lock().unwrap();
    let _ = notify_new_connection(&cm, &their_id, Event::NewPeer(Ok(()), their_id), &event_tx);

    let connection = register_tcp_connection(connection_map.clone(),
                                             their_id,
                                             network_rx,
                                             network_tx,
                                             event_tx,
                                             our_addr,
                                             their_addr,
                                             EstablishmentMethod::Rendezvous);

    // Hole-punched connections take priority over any other kind of connection.
    let _ = cm.insert(their_id, connection);
    Ok(())
}

pub fn connect_tcp_endpoint(remote_addr: SocketAddr,
                            heart_beat_timeout: Duration,
                            inactivity_timeout: Duration,
                            our_public_key: PublicKey,
                            event_tx: ::CrustEventSender,
                            connection_map: Arc<Mutex<HashMap<PeerId, Connection>>>,
                            expected_peers: Option<Arc<Mutex<HashSet<PeerId>>>>,
                            their_expected_id: Option<PeerId>,
                            version_hash: u64)
                            -> io::Result<()> {
    let (network_input, writer) = try!(tcp_connections::connect_tcp(remote_addr.clone(),
                                                                    heart_beat_timeout,
                                                                    inactivity_timeout));
    let our_addr = SocketAddr(try!(network_input.local_addr()));
    let their_addr = SocketAddr(try!(network_input.peer_addr()));
    let conn_id: u32 = rand::random();

    let mut network_rx = Receiver::tcp(network_input);
    let (their_id, event) = match their_expected_id {
        None => {
            match writer.send(WriteEvent::Write(CrustMsg::BootstrapRequest(our_public_key,
                                                                           version_hash,
                                                                           conn_id))) {
                Ok(()) => (),
                Err(_) => {
                    error!("Receiver shut down");
                    return Err(io::Error::new(io::ErrorKind::Other, "Receiver shut down"));
                }
            };
            match network_rx.receive() {
                Ok(CrustMsg::BootstrapResponse(key)) => {
                    if key == our_public_key {
                        return Err(io::Error::new(io::ErrorKind::Other, "Connected to ourselves."));
                    }
                    let their_id = peer_id::new_id(key);
                    (their_id, Some(Event::BootstrapConnect(their_id)))
                }

                Ok(m) => {
                    return Err(io::Error::new(io::ErrorKind::Other,
                                              format!("Invalid crust message from peer during \
                                                       bootstrap attempt: {:?}",
                                                      m)))
                }
                Err(e) => return Err(e),
            }
        }
        Some(id) => {
            match writer.send(WriteEvent::Write(CrustMsg::Connect(our_public_key, version_hash, conn_id))) {
                Ok(()) => (),
                Err(_) => {
                    error!("Receiver shut down");
                    return Err(io::Error::new(io::ErrorKind::Other, "Receiver shut down"));
                }
            }
            match network_rx.receive() {
                Ok(CrustMsg::Connect(key, v, _)) => {
                    let their_id = peer_id::new_id(key);
                    if v != version_hash {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                                  "Incompatible protocol version.".to_owned()));
                    }
                    if their_id != id {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                                  format!("Connected to the wrong peer: {}.",
                                                          their_id)));
                    }

                    if let Some(expected_peers) = expected_peers {
                        let mut expected_peers = expected_peers.lock().unwrap();
                        if expected_peers.remove(&their_id) {
                            (their_id, Some(Event::NewPeer(Ok(()), their_id)))
                        } else {
                            (their_id, None)
                        }
                    } else {
                        unreachable!("Expected Peers cannot be None when calling service connect");
                    }
                }
                Ok(m) => {
                    return Err(io::Error::new(io::ErrorKind::Other,
                                              format!("Invalid crust message from peer during \
                                                       connect attempt: {:?}",
                                                      m)))
                }
                Err(e) => return Err(e),
            }
        }
    };

    let mut cm = connection_map.lock().unwrap();
    if let Some(event) = event {
        let _ = notify_new_connection(&cm, &their_id, event, &event_tx);
    }

    let network_tx = RaiiSender(writer);
    let connection = register_tcp_connection(connection_map.clone(),
                                             their_id,
                                             network_rx,
                                             network_tx,
                                             event_tx,
                                             our_addr,
                                             their_addr,
                                             EstablishmentMethod::Direct(conn_id));
    match cm.entry(their_id) {
        Entry::Occupied(ref mut oe) => match oe.get().establishment_method {

            // Rendezvous connects take precedence over direct connects
            EstablishmentMethod::Rendezvous => (),

            // Go with the higher conn_id
            EstablishmentMethod::Direct(old_conn_id) => {
                if conn_id > old_conn_id {
                    let _ = oe.insert(connection);
                }
            },
        },
        Entry::Vacant(ve) => {
            let _ = ve.insert(connection);
        },
    };

    Ok(())
}

fn register_tcp_connection(connection_map: Arc<Mutex<HashMap<PeerId, Connection>>>,
                           their_id: PeerId,
                           network_rx: Receiver,
                           network_tx: RaiiSender,
                           event_tx: ::CrustEventSender,
                           our_addr: SocketAddr,
                           their_addr: SocketAddr,
                           establishment_method: EstablishmentMethod)
                           -> Connection {
    let closed = Arc::new(AtomicBool::new(false));
    let closed_clone = closed.clone();

    let joiner = RaiiThreadJoiner::new(thread!("TcpNetworkReader", move || {
        start_rx(network_rx, their_id, event_tx, closed_clone, connection_map);
    }));

    Connection {
        protocol: Protocol::Tcp,
        our_addr: our_addr,
        their_addr: their_addr,
        establishment_method: establishment_method,
        network_tx: network_tx,
        _network_read_joiner: joiner,
        closed: closed,
    }
}


pub fn start_tcp_accept(port: u16,
                        heart_beat_timeout: Duration,
                        inactivity_timeout: Duration,
                        our_contact_info: Arc<Mutex<StaticContactInfo>>,
                        our_public_key: PublicKey,
                        event_tx: ::CrustEventSender,
                        connection_map: Arc<Mutex<HashMap<PeerId, Connection>>>,
                        // TODO(canndrew): We currently don't share static contact infos on
                        // accepting a connection
                        _bootstrap_cache: Arc<Mutex<BootstrapHandler>>,
                        expected_peers: Arc<Mutex<HashSet<PeerId>>>,
                        mapping_context: Arc<MappingContext>,
                        version_hash: u64)
                        -> io::Result<RaiiTcpAcceptor> {
    let addr = net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
    let tcp_builder_listener = try!(nat_traversal::new_reusably_bound_tcp_socket(&addr));

    let mapped_tcp_socket = match nat_traversal::MappedTcpSocket::map(tcp_builder_listener,
                                                                      mapping_context.as_ref())
                                      .result_log() {
        Ok(mapped_tcp_socket) => mapped_tcp_socket,
        Err(err) => return Err(From::from(err)),
    };
    let tcp_builder_listener = mapped_tcp_socket.socket;
    let mut addrs: Vec<SocketAddr> = mapped_tcp_socket.endpoints
                                                      .into_iter()
                                                      .map(|m| m.addr)
                                                      .collect();

    let listener = try!(tcp_builder_listener.listen(1));
    let new_port = try!(listener.local_addr()).port(); // Useful if supplied port was 0

    // This is to help with some particularly nasty routers (such as @andreas') that won't map a
    // port correctly even if port forwarding is set up. They might be configured to forward
    // external port 1234 to internal port 5678 but an outgoing connection from port 5678 won't
    // appear from 1234, making external mapper servers useless.
    for i in 0..addrs.len() {
        let ip = addrs[i].ip();
        let addr = SocketAddr(net::SocketAddr::new(ip, new_port));
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }

    unwrap_result!(our_contact_info.lock()).tcp_acceptors.extend(addrs);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let cloned_stop_flag = stop_flag.clone();

    let joiner = RaiiThreadJoiner::new(thread!("TcpAcceptorThread", move || {
        loop {
            let (stream, _) = match listener.accept() {
                Ok(tuple) => tuple,
                Err(err) => {
                    error!("Error in TcpListener's accept: {}", err);
                    break;
                }
            };

            if cloned_stop_flag.load(Ordering::SeqCst) {
                let _ = stream.shutdown(Shutdown::Both);
                break;
            }

            let (network_input, writer) = match tcp_connections::upgrade_tcp(stream,
                                                                             heart_beat_timeout,
                                                                             inactivity_timeout) {
                Ok((stream, writer_tx)) => (stream, writer_tx),
                Err(e) => {
                    debug!("TCP Acceptor failed to upgrade connected stream: {:?}", e);
                    continue;
                }
            };

            let (our_addr, their_addr) = match (network_input.local_addr(),
                                                network_input.peer_addr()) {
                (Ok(our_addr), Ok(their_addr)) => (SocketAddr(our_addr), SocketAddr(their_addr)),
                (_, Err(e)) | (Err(e), _) => {
                    debug!("TCP Acceptor failed to get endpoints for connected stream: {:?}",
                           e);
                    continue;
                }
            };

            let mut network_rx = Receiver::tcp(network_input);

            let msg = network_rx.receive();
            let (their_id, event, conn_id) = match msg {
                Ok(CrustMsg::BootstrapRequest(k, v, conn_id)) => {
                    match writer.send(WriteEvent::Write(CrustMsg::BootstrapResponse(our_public_key))) {
                        Ok(()) => (),
                        Err(_) => {
                            error!("Reciever shutdown!");
                            continue;
                        },
                    }
                    if our_public_key == k {
                        error!("Connected to ourselves");
                        continue;
                    }
                    if v != version_hash {
                        error!("Incompatible protocol version.");
                        continue;
                    }

                    let peer_id = peer_id::new_id(k);
                    (peer_id, Event::BootstrapAccept(peer_id), conn_id)
                }
                Ok(CrustMsg::Connect(k, v, conn_id)) => {
                    if v != version_hash {
                        error!("Incompatible protocol version.");
                        continue;
                    }
                    if our_public_key == k {
                        error!("Connected to ourselves");
                        continue;
                    }
                    let peer_id = peer_id::new_id(k);
                    let mut expected_peers = expected_peers.lock().unwrap();
                    if expected_peers.remove(&peer_id) {
                        match writer.send(WriteEvent::Write(CrustMsg::Connect(our_public_key,
                                                                              version_hash, conn_id))) {
                            Ok(()) => (),
                            Err(_) => {
                                error!("Receiver shutdown!");
                                continue;
                            }
                        }
                    } else {
                        continue;
                    }

                    (peer_id, Event::NewPeer(Ok(()), peer_id), conn_id)
                }
                Ok(m) => {
                    error!("Unexpected crust msg on tcp accept: {:?}", m);
                    continue;
                }
                Err(e) => {
                    error!("Invalid crust msg on tcp accept: {}", e);
                    continue;
                }
            };

            let mut cm = unwrap_result!(connection_map.lock());
            if notify_new_connection(&cm, &their_id, event, &event_tx).is_err() {
                break;
            }
            let connection = register_tcp_connection(connection_map.clone(),
                                                     their_id,
                                                     network_rx,
                                                     RaiiSender(writer),
                                                     event_tx.clone(),
                                                     our_addr,
                                                     their_addr,
                                                     EstablishmentMethod::Direct(conn_id));
            match cm.entry(their_id) {
                Entry::Occupied(ref mut oe) => match oe.get().establishment_method {
                    // Rendezvous connects take precedence over direct connects
                    EstablishmentMethod::Rendezvous => (),
                    EstablishmentMethod::Direct(old_conn_id) => {
                        if conn_id > old_conn_id {
                            let _ = oe.insert(connection);
                        }
                    },
                },
                Entry::Vacant(ve) => {
                    let _ = ve.insert(connection);
                },
            }
        }
    }));

    Ok(RaiiTcpAcceptor {
        port: new_port,
        stop_flag: stop_flag,
        _raii_joiner: joiner,
    })
}

fn start_rx(mut network_rx: Receiver,
            their_id: PeerId,
            event_tx: ::CrustEventSender,
            closed: Arc<AtomicBool>,
            connection_map: Arc<Mutex<HashMap<PeerId, Connection>>>) {
    loop {
        match network_rx.receive() {
            Ok(msg) => {
                match msg {
                    CrustMsg::Message(msg) => {
                        if let Err(err) = event_tx.send(Event::NewMessage(their_id, msg)) {
                            error!("Error sending message to {:?}: {:?}", their_id, err);
                            break;
                        }
                    }
                    CrustMsg::Heartbeat => (),
                    m => error!("Unexpected message in start_rx: {:?}", m),
                }
            }
            Err(err) => {
                debug!("Error receiving from {:?}: {:?}", their_id, err);
                break;
            }
        }
    }

    closed.store(true, Ordering::Relaxed);
    // Drop the connection in a separate thread, because the destructor joins _this_ thread.
    let _ = thread!("ConnectionDropper", move || {
        let mut lock = unwrap_result!(connection_map.lock());
        if let Entry::Occupied(entry) = lock.entry(their_id) {
            if entry.get().is_closed() {
                let _ = entry.remove();
                trace!("Sending LostPeer({}) event.", their_id);
                if let Err(err) = event_tx.send(Event::LostPeer(their_id)) {
                    error!("Failed to send LostPeer({}) event: {:?}", their_id, err);
                }
            }
        }
        print_connection_stats(&lock);
    });
}

fn notify_new_connection(connection_map: &HashMap<PeerId, Connection>,
                         peer_id: &PeerId,
                         event: Event,
                         event_tx: &::CrustEventSender)
                         -> Result<(), CrustEventSenderError> {
    print_connection_stats(connection_map);
    if !connection_map.contains_key(peer_id) {
        event_tx.send(event)
    } else {
        Ok(())
    }
}

pub fn print_connection_stats(connection_map: &HashMap<PeerId, Connection>) {
    let mut punched = 0usize;
    let mut direct = 0usize;
    for (_peer_id, conn) in connection_map {
        if let EstablishmentMethod::Rendezvous = conn.establishment_method {
            punched += 1;
        } else {
            direct += 1;
        };
    }
    debug!("Stats - {} connections - direct: {}, punched: {}",
           direct + punched,
           direct,
           punched);
}

#[cfg(test)]
mod test {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
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
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.254.\
                                                                                 200:30000"))),
                establishment_method: EstablishmentMethod::Rendezvous,
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
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.254.\
                                                                                 200:30000"))),
                establishment_method: EstablishmentMethod::Rendezvous,
                network_tx: RaiiSender(tx),
                _network_read_joiner: raii_joiner,
                closed: Arc::new(AtomicBool::new(false)),
            }
        };

        assert_eq!(hash(&connection_0), hash(&connection_0));
        assert_eq!(hash(&connection_0), hash(&connection_1));


        // our_addr different
        let connection_3 = {
            let (tx, _) = mpsc::channel();
            let raii_joiner = RaiiThreadJoiner::new(thread!("DummyThread", move || ()));

            Connection {
                protocol: Protocol::Tcp,
                our_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("10.199.254.201:\
                                                                               30000"))),
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.254.\
                                                                                 200:30000"))),
                establishment_method: EstablishmentMethod::Rendezvous,
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
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.253.\
                                                                                 200:30000"))),
                establishment_method: EstablishmentMethod::Rendezvous,
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
                their_addr: SocketAddr(unwrap_result!(net::SocketAddr::from_str("11.199.254.\
                                                                                 200:30000"))),
                establishment_method: EstablishmentMethod::Rendezvous,
                network_tx: RaiiSender(tx),
                _network_read_joiner: raii_joiner,
                closed: Arc::new(AtomicBool::new(true)),
            }
        };

        assert_eq!(hash(&connection_5), hash(&connection_5));
        assert!(hash(&connection_0) != hash(&connection_5));
    }
}
