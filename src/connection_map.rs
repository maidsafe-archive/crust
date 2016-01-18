use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io;
use std::net;

use ip::{IpAddr, SocketAddrExt};
//use maidsafe_utilities::thread::RaiiThreadJoiner;

use socket_addr::SocketAddr;
use transport;
use event::Event;
use connection::Connection;
use transport::Handshake;
use transport::{Transport, Message};
use Endpoint;

pub struct ConnectionData {
    pub message_sender: transport::Sender,
    pub mapper_address: Option<SocketAddr>,
    pub mapper_external_address: Option<SocketAddr>,
    //pub reader_thread: RaiiThreadJoiner,
}

pub struct ConnectionMap {
    inner: Arc<Mutex<ConnectionMapInner>>,
}

struct ConnectionMapInner {
    connections: HashMap<Connection, ConnectionData>,
    event_sender: ::CrustEventSender,
}

impl Drop for ConnectionMap {
    fn drop(&mut self) {
        println!("Dropping ConnectionMap");
    }
}

impl ConnectionMap {
    pub fn new(event_sender: ::CrustEventSender) -> ConnectionMap {
        ConnectionMap {
            inner: Arc::new(Mutex::new(ConnectionMapInner::new(event_sender))),
        }
    }

    pub fn get_ordered_helping_nodes(&self) -> Vec<SocketAddr> {
        let inner = unwrap_result!(self.inner.lock());
        inner.get_ordered_helping_nodes()
    }

    pub fn is_connected_to(&self, endpoint: &Endpoint) -> bool {
        let inner = unwrap_result!(self.inner.lock());
        inner.is_connected_to(endpoint)
    }

    /*
    pub fn get(&self, connection: &Connection) -> Option<ConnectionData> {
        let inner = unwrap_result!(self.inner.lock());
        inner.get(connection)
    }
    */
    
    pub fn send(&self, connection: Connection, bytes: Vec<u8>) {
        let mut inner = unwrap_result!(self.inner.lock());
        inner.send(connection, bytes)
    }

    pub fn register_connection(&self,
                               handshake: Handshake,
                               transport: Transport,
                               event_to_user: Event)
                               -> io::Result<Connection> {
        let me = self.inner.clone();
        let mut inner = unwrap_result!(self.inner.lock());
        inner.register_connection(handshake, transport, event_to_user, me)
    }

    pub fn unregister_connection(&self, connection: Connection) {
        let mut inner = unwrap_result!(self.inner.lock());
        inner.unregister_connection(connection)
    }
}

impl ConnectionMapInner {
    pub fn new(event_sender: ::CrustEventSender) -> ConnectionMapInner {
        ConnectionMapInner {
            connections: HashMap::new(),
            event_sender: event_sender,
        }
    }

    pub fn get_ordered_helping_nodes(&self) -> Vec<SocketAddr> {
        let mut addrs = self.connections
                            .iter()
                            .filter_map(|pair| pair.1.mapper_address.clone())
                            .collect::<Vec<_>>();

        addrs.sort_by(|addr1, addr2| {
            ::util::heuristic_geo_cmp(&SocketAddrExt::ip(&**addr1), &SocketAddrExt::ip(&**addr2))
                .reverse()
        });

        addrs
    }

    pub fn is_connected_to(&self, endpoint: &Endpoint) -> bool {
        for connection in self.connections.keys() {
            if connection.peer_endpoint() == *endpoint {
                return true;
            }
        }
        false
    }

    /*
    pub fn get(&self, connection: &Connection) -> Option<ConnectionData> {
        self.connections.get(connection).map(|c| c.clone())
    }
    */

    pub fn send(&mut self, connection: Connection, bytes: Vec<u8>) {
        let dropped = match self.connections.get_mut(&connection) {
            Some(mut connection_data) => {
                let writer = &mut connection_data.message_sender;
                if let Err(_what) = writer.send(&Message::UserBlob(bytes)) {
                    true
                }
                else {
                    false
                }
            }
            None => {
                // Connection already destroyed or never existed.
                false
            }
        };
        if dropped {
            self.unregister_connection(connection);
        };
    }

    pub fn register_connection(&mut self,
                               handshake: Handshake,
                               transport: Transport,
                               event_to_user: Event,
                               me: Arc<Mutex<ConnectionMapInner>>)
                               -> io::Result<Connection> {
        println!("registering connection: {:?}", handshake);
        let connection_id = transport.connection_id.clone();
        let mut receiver = transport.receiver;
        let sender = transport.sender;

        debug_assert!(!self.connections.contains_key(&connection_id));

        let mapper_addr = match handshake.mapper_port {
            Some(port) => {
                let peer_addr = connection_id.peer_endpoint()
                                             .ip();
                match peer_addr {
                    IpAddr::V4(a) => {
                        Some(SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(a, port))))
                    },
                    // FIXME(dirvine) Handle ip6 :10/01/2016
                    IpAddr::V6(_) => unimplemented!(),
                }
            },
            None => None,
        };
        // We need to insert the event into event_sender *before* the
        // reading thread starts. It is because the reading thread
        // also inserts events into the pipe and if done very quickly
        // they may be inserted in wrong order.
        let _ = self.event_sender.send(event_to_user);

        let connection_id_mv = connection_id.clone();
        // start the reading thread
        let event_sender = self.event_sender.clone();
        //let reader_thread = RaiiThreadJoiner::new(thread!("reader", move || {
        // TODO (canndrew): We risk leaking this thread if we don't keep a handle to it.
        let _ = thread!("reader", move || {
            println!("In reader thread");
            while let Ok(msg) = receiver.receive() {
                println!("reader thread got message: {:?}", msg);
                match msg {
                    Message::UserBlob(msg) => {
                        if event_sender.send(Event::NewMessage(connection_id_mv.clone(), msg)).is_err() {
                            break;
                        }
                    }
                    Message::HolePunchAddress(a) => {
                        let connection = connection_id_mv.clone();
                        let mut inner = unwrap_result!(me.lock());
                        if let Some(cd) = inner.connections.get_mut(&connection) {
                            cd.mapper_external_address = Some(a);
                        }
                    }
                }
            }
            println!("reader thread exiting");
            let mut inner = unwrap_result!(me.lock());
            inner.unregister_connection(connection_id_mv);
        });
        let connection_data = ConnectionData {
            message_sender: sender,
            mapper_address: mapper_addr,
            mapper_external_address: handshake.external_addr,
            //reader_thread: reader_thread,
        };
        println!("really registered");
        let _ = self.connections.insert(connection_id.clone(), connection_data);

        Ok(connection_id)
    }

    pub fn unregister_connection(&mut self, connection: Connection) {
        println!("unregistering connection");
        // Avoid sending duplicate LostConnection event.
        if self.connections.remove(&connection).is_none() {
            println!("zoom");
            return;
        }

        let _ = self.event_sender.send(Event::LostConnection(connection));
    }
}

