extern crate crust;
extern crate cbor;
extern crate rustc_serialize;

use std::sync::{Mutex, Arc};
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver};
use std::thread;
use std::thread::spawn;
use rustc_serialize::{Decodable, Encodable};
use cbor::{Encoder, Decoder};
use crust::connection_manager;
use crust::connection_manager::{ConnectionManager, Bytes, Event};
use crust::transport::{Endpoint, Port};

const  NETWORK_SIZE: u32 = 10;
const  MESSAGE_PER_NODE: u32 = 100;

struct Node {
    conn_mgr: ConnectionManager,
    listenig_end_point: Endpoint
}

#[derive(Debug)]
struct Stats {
    new_connections_count: u32,
    messages_count: u32,
    lost_connection_count: u32
}

impl Node {
    pub fn new(cm: ConnectionManager) -> Node {
        match cm.start_listening(vec![Port::Tcp(0)]) {
            Ok(end_points) => Node { conn_mgr: cm, listenig_end_point: end_points[0].clone() },
            Err(_) => panic!("not listening")
        }
    }
}

struct Network {
    nodes: Vec<Node>
}

impl Network {
    pub fn add(&mut self) -> Receiver<Event> {
        let (cm_i, cm_o) = channel();
        let cm = connection_manager::ConnectionManager::new(cm_i);
        self.nodes.push(Node::new(cm));
        cm_o
    }
}

fn encode<T>(value: &T) -> Bytes where T: Encodable
{
    let mut enc = Encoder::from_memory();
    let _ = enc.encode(&[value]);
    enc.into_bytes()
}

fn decode<T>(bytes: Bytes) -> T where T: Decodable {
    let mut dec = Decoder::from_bytes(&bytes[..]);
    dec.decode().next().unwrap().unwrap()
}

fn main() {
    let run_cm = |stats: Arc<Mutex<Stats>>, o: Receiver<Event>| {
        spawn(move || {
            for i in o.iter() {
                let mut stats = stats.lock().unwrap();
                match i {
                    Event::NewConnection(other_ep) => {
                        println!("Connected to --> {:?}", other_ep);
                        stats.new_connections_count += 1;
                    },
                    Event::NewMessage(from_ep, data) => {
                        println!("New message from {:?} data:{:?}",
                                 from_ep, decode::<String>(data));
                        stats.messages_count += 1;
                        if stats.messages_count == MESSAGE_PER_NODE * (NETWORK_SIZE - 1) {
                            break;
                        }
                    },
                    Event::LostConnection(other_ep) => {
                        println!("Lost connection to {:?}", other_ep);
                        stats.lost_connection_count += 1;
                    },
                    _ => println!("unhandled"),
                }
            }
            println!("done");
        })
    };

    let mut network = Network { nodes: Vec::new() };
    let mut stats = Vec::new();
    let mut runners = Vec::new();

    for _ in 0..NETWORK_SIZE {
        let receiver = network.add();
        let stat = Arc::new(Mutex::new(Stats {new_connections_count: 0, messages_count: 0,
             lost_connection_count: 0} ));
        let stat_copy = stat.clone();
        let runner = run_cm(stat_copy, receiver);
        stats.push(stat);
        runners.push(runner);
    }

    let mut listening_end_points = Vec::new();
    for node in network.nodes.iter() {
        listening_end_points.push(node.listenig_end_point.clone());
    }

    for node in network.nodes.iter() {
        for end_point in listening_end_points.iter().filter(|&ep| node.listenig_end_point.ne(ep)) {
            node.conn_mgr.connect(vec![end_point.clone()]);
        }
    }

    for node in network.nodes.iter() {
        for end_point in listening_end_points.iter().filter(|&ep| node.listenig_end_point.ne(ep)) {
            for _ in 0..MESSAGE_PER_NODE {
                let _ = node.conn_mgr.send(end_point.clone(), encode(&"message".to_string()));
            }
        }
    }

    for _ in 0..NETWORK_SIZE {
        network.nodes.remove(0);
    }

    thread::sleep_ms(100 * NETWORK_SIZE);
    for stat in stats {
        let stat = stat.clone();
        let stat = stat.lock().unwrap();
        assert_eq!(stat.new_connections_count, NETWORK_SIZE - 1);
        assert_eq!(stat.messages_count,  MESSAGE_PER_NODE * (NETWORK_SIZE - 1));
        assert_eq!(stat.lost_connection_count, 0);
    }

    for runner in runners {
        assert!(runner.join().is_ok());
    }
}
