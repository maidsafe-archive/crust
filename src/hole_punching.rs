use std::net::UdpSocket;
use std::io;
use std::net;
use std::net::TcpStream;
use std::sync::{Arc, RwLock};
use std::sync::mpsc::Sender;
use std::sync::atomic::{Ordering, AtomicBool};
use std::time::Duration;

use periodic_sender::PeriodicSender;
use socket_utils::RecvUntil;
use endpoint::{Protocol, Endpoint};
use socket_addr::{SocketAddr, SocketAddrV4};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::{serialise, deserialise};
use tcp_connections;
use event::WriteEvent;

#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct HolePunch {
    pub secret: Option<[u8; 4]>,
    pub ack: bool,
}

