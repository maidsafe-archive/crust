use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;
use std::sync::mpsc;
use std::collections::HashMap;
use std::io;
use std::net;

use ip::{IpAddr, SocketAddrExt};

use socket_addr::SocketAddr;
use transport;
use event::Event;
use connection::Connection;
use transport::handshake::Handshake;
use transport::{Transport, Message};
use Endpoint;

pub struct ConnectionData {
    pub message_sender: transport::Sender,
    pub mapper_address: Option<SocketAddr>,
    pub mapper_external_address: Option<SocketAddr>,
}

pub struct ConnectionMap {
    inner: Arc<Mutex<ConnectionMapInner>>,
}

struct ConnectionMapInner {
    connections: HashMap<Connection, ConnectionData>,
    event_sender: ::CrustEventSender,
}

impl ConnectionMap {
    pub fn new(event_sender: ::CrustEventSender) -> ConnectionMap {
        ConnectionMap {
            inner: Arc::new(Mutex::new(ConnectionMapInner::new(event_sender))),
        }
    }

    pub fn get_ordered_helping_nodes(&self) -> Vec<SocketAddr> {
        let mut inner = unwrap_result!(self.inner.lock());
        inner.get_ordered_helping_nodes()
    }

    pub fn is_connected_to(&self, endpoint: &Endpoint) -> bool {
        let mut inner = unwrap_result!(self.inner.lock());
        inner.is_connected_to(endpoint)
    }

    pub fn get(&self, connection: &Connection) -> Option<ConnectionData> {
        let inner = unwrap_result!(self.inner.lock());
        inner.get(connection)
    }

    pub fn register_connection(&self,
                               handshake: Handshake,
                               transport: Transport,
                               event_to_user: Event)
                               -> io::Result<Connection> {
        let me = self.inner.clone();
        let mut inner = unwrap_result!(self.inner.lock());
        inner.register_connection(handshake, transport, event_to_user)
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
            if connection.peer_endpoint() == endpoint {
                return true;
            }
        }
        false
    }

    pub fn get(&self, connection: &Connection) -> Option<ConnectionData> {
        self.connections.get(connection)
    }

    pub fn register_connection(&mut self,
                               handshake: Handshake,
                               transport: Transport,
                               event_to_user: Event,
                               me: Arc<Mutex<ConnectionMap>>)
                               -> io::Result<Connection> {
        let connection = transport.connection_id.clone();
        debug_assert!(!self.connections.contains_key(&connection));

        let (tx, rx) = mpsc::channel();
        let mapper_addr = match handshake.mapper_port {
            Some(port) => {
                let peer_addr = transport.connection_id
                                         .peer_endpoint()
                                         .ip();
                match peer_addr {
                    IpAddr::V4(a) => {
                        SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(a, port)))
                    },
                    // FIXME(dirvine) Handle ip6 :10/01/2016
                    IpAddr::V6(a) => unimplemented!(),
                }
            },
        };
        let connection_data = ConnectionData {
            message_sender: transport.sender,
            mapper_address: mapper_addr,
            mapper_external_address: handshake.external_addr,
        };
        // We need to insert the event into event_sender *before* the
        // reading thread starts. It is because the reading thread
        // also inserts events into the pipe and if done very quickly
        // they may be inserted in wrong order.
        let _ = self.connections.insert(connection.clone(), connection_data);
        let _ = self.event_sender.send(event_to_user);

        // start the reading thread
        let event_sender = self.event_sender.clone();
        let _ = Self::new_thread("reader", move || {
            while let Ok(msg) = transport.receiver.receive() {
                match msg {
                    Message::UserBlob(msg) => {
                        if event_sender.send(Event::NewMessage(connection.clone(), msg)).is_err() {
                            break;
                        }
                    }
                    Message::HolePunchAddress(a) => {
                        let connection = connection.clone();
                        if let Some(cd) = self.connections.get_mut(&connection) {
                            cd.mapper_external_address = Some(a);
                        }
                    }
                }
            }
            me.unregister_connection(connection);
        });

        Ok(transport.connection_id)
    }

    pub fn unregister_connection(&mut self, connection: Connection) {
        // Avoid sending duplicate LostConnection event.
        if self.connections.remove(&connection).is_none() {
            return;
        }

        let _ = self.event_sender.send(Event::LostConnection(connection));
    }
}

