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

// String.as_str() is unstable; waiting RFC revision
// http://doc.rust-lang.org/nightly/std/string/struct.String.html#method.as_str
#![feature(core, exit_status)]

extern crate core;
extern crate crust;
extern crate rustc_serialize;
extern crate docopt;
extern crate rand;
extern crate time;

use core::iter::FromIterator;
use docopt::Docopt;
use rand::random;
use rand::Rng;
use rustc_serialize::{Decodable, Decoder};
use std::cmp;
use std::sync::mpsc::channel;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread::spawn;

use crust::{ConnectionManager, Endpoint, Port};

static USAGE: &'static str = "
Usage:
  crust_node [options] [<peer>...]

The node will try and bootstrap off one of the peers if any are provided.  If
none are provided, or if connecting to any of the peers fails, the UDP beacon
will be used.  If no beacon port is specified in the options, then port 9999
will be chosen.  If no listening port is supplied, a random port for each
supported protocol will be chosen.

Options:
  -t PORT, --tcp-port=PORT  Start listening on the specified TCP port.
  -b PORT, --beacon=PORT    Set the beacon port.  If the node can, it will
                            listen for UDP broadcasts on this port.  If
                            bootstrapping using provided contacts or the cached
                            contacts fails, the node will broadcast to the
                            beacon port in an attempt to connect to a peer on
                            the same LAN.
  -s RATE, --speed=RATE     Send random data at maximum speed (bytes/second).
  -h, --help                Display this help message.
";

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_peer: Vec<PeerEndpoint>,
    flag_tcp_port: Option<u16>,
    flag_beacon: Option<u16>,
    flag_speed: Option<u64>,
    flag_help: bool,
}

#[derive(Debug)]
enum PeerEndpoint {
    Tcp(SocketAddr),
}

impl Decodable for PeerEndpoint {
    fn decode<D: Decoder>(d: &mut D)->Result<PeerEndpoint, D::Error> {
        let str = try!(d.read_str());
        let address = match SocketAddr::from_str(&str) {
            Ok(addr) => addr,
            Err(what) => {
                println!("Could not decode {} as valid IPv4 or IPv6 address.", str);
                return Err(d.error("Failed to decode address."))
            },
        };
        Ok(PeerEndpoint::Tcp(address))
    }
}

fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}

fn print_input_line() {
    print!("Enter command (stop | connect <endpoint> | send <endpoint> <message>)>");
    let _ = io::stdout().flush();
}

// simple "NodeInfo", without PKI
#[derive(Clone)]
struct CrustNode {
    pub endpoint: Endpoint,
    pub connected: bool
}

impl CrustNode {
    pub fn new(endpoint: Endpoint, connected: bool) -> CrustNode {
        CrustNode{
            endpoint: endpoint,
            connected: connected
        }
    }
    pub fn set_connected(&mut self) {
        self.connected = true;
    }
    pub fn set_disconnected(&mut self) {
        self.connected = false;
    }
}

struct FlatWorld {
    crust_nodes: Vec<CrustNode>,
    performance_start: time::SteadyTime,
    performance_interval: time::Duration,
    received_msgs: u32,
    received_bytes: u32
}

// simple "routing table" without any structure
impl FlatWorld {
    pub fn new() -> FlatWorld {
        FlatWorld {
            crust_nodes: Vec::with_capacity(40),
            performance_start: time::SteadyTime::now(),
            performance_interval: time::Duration::seconds(10),
            received_msgs: 0,
            received_bytes: 0
        }
    }

    // Will add node if not duplicated.  Returns true when added.
    pub fn add_node(&mut self, new_node: CrustNode) -> bool {
        if self.crust_nodes.iter()
                           .filter(|node| node.endpoint == new_node.endpoint)
                           .count() == 0 {
            self.crust_nodes.push(new_node);
            return true;
        }
        for node in self.crust_nodes.iter_mut().filter(|node| node.endpoint == new_node.endpoint) {
            node.set_connected();
        }
        return false;
    }

    pub fn drop_node(&mut self, lost_node: CrustNode) {
        for node in self.crust_nodes.iter_mut().filter(|node| node.endpoint == lost_node.endpoint) {
            node.set_disconnected();
        }
    }

    pub fn print_connected_nodes(&self) {
        let connected_nodes =
            self.crust_nodes.iter().filter_map(|node|
                if node.connected {
                    Some(match node.endpoint { Endpoint::Tcp(socket_addr) => socket_addr })
                } else {
                    None
                }).collect::<Vec<_>>();
        if connected_nodes.len() == 1 {
            println!("Connected nodes: {}", connected_nodes[0]);
        } else if connected_nodes.len() > 1 {
            print!("Connected nodes: {}", connected_nodes[0]);
            for i in 1..connected_nodes.len() {
                print!(",{}", connected_nodes[i]);
            }
            println!("");
        }
    }

    // pub fn get_all_nodes(&self) -> Vec<CrustNode> {
    //     self.crust_nodes.clone()
    // }

    pub fn record_received(&mut self, msg_size: u32) {
        self.received_msgs += 1;
        self.received_bytes += msg_size;
        if self.received_msgs == 1 {
            self.performance_start = time::SteadyTime::now();
        }
        if self.performance_start + self.performance_interval < time::SteadyTime::now() {
            println!("received {} msgs with total size of {} bytes in last 10 seconds",
                     self.received_msgs, self.received_bytes);
            self.received_msgs = 0;
            self.received_bytes = 0;
        }
    }
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());

    // Convert peer endpoints to usable bootstrap list.
    let bootstrap_peers = if args.arg_peer.is_empty() {
        None
    } else {
        Some(Vec::<Endpoint>::from_iter(args.arg_peer.iter().map(|endpoint| {
            Endpoint::Tcp(match *endpoint { PeerEndpoint::Tcp(address) => address, })
        })))
    };

    // Convert requested listening port(s) to usable collection.
    let mut listening_hints: Vec<Port> = vec![];
    match args.flag_tcp_port {
        Some(port) => listening_hints.push(Port::Tcp(port)),
        None => (),
    };

    // Set up beacon port
    let beacon_port = match args.flag_beacon {
        Some(port) => Some(port),
        None => Some(9999u16),
    };
                                                                                        println!("     bootstrap_peers: {:?}", bootstrap_peers);
                                                                                        println!("     listening_hints: {:?}", listening_hints);
                                                                                        println!("     beacon_port: {:?}", beacon_port);
                                                                                        println!("     flag_speed: {:?}", args.flag_speed);

    // Start event-handling thread
    let (channel_sender, channel_receiver) = channel();
    let mut my_flat_world: FlatWorld = FlatWorld::new();
    spawn(move || {
        loop {
            let event = channel_receiver.recv();
            if event.is_err() {
                println!("Channel error - stopped listening.");
                break;
            }

            match event.unwrap() {
                crust::Event::NewMessage(endpoint, bytes) => {
                    my_flat_world.record_received(bytes.len() as u32);
                    println!("\n\nReceived from {:?} message: {}", endpoint,
                             match String::from_utf8(bytes) {
                                 Ok(msg) => msg,
                                 Err(_) => "unknown msg".to_string()
                             });
                    print_input_line();
                },
                crust::Event::NewConnection(endpoint) => {
                    println!("\n\nConnected to peer at {:?}", endpoint);
                    my_flat_world.add_node(CrustNode::new(endpoint, true));
                    my_flat_world.print_connected_nodes();
                    print_input_line();
                },
                crust::Event::LostConnection(endpoint) => {
                    println!("\n\nLost connection to peer at {:?}", endpoint);
                    print_input_line();
                    my_flat_world.drop_node(CrustNode::new(endpoint, false));
                }
            }
        }
    });

    // Construct ConnectionManager and start listening
    let mut connection_manager = ConnectionManager::new(channel_sender);
    let listening_endpoints = match connection_manager.start_listening(listening_hints,
                                                                       beacon_port) {
        Ok(endpoints) => endpoints,
        Err(e) => {
            println!("Connection manager failed to start listening: {}", e);
            std::env::set_exit_status(1);
            return;
        }
    };
    print!("Listening for new connections on ");
    for endpoint in &listening_endpoints.0 {
        print!("{:?}, ", *endpoint);
    };
    match listening_endpoints.1 {
        Some(beacon_port) => println!("and listening for UDP broadcast on port {}.", beacon_port),
        None => println!("and not listening for UDP broadcasts."),
    };

    // Try to bootstrap.  If no peer endpoints were provided and bootstrapping fails, assume this is
    // OK, i.e. this is the first node of a new network.
    match connection_manager.bootstrap(bootstrap_peers.clone(), beacon_port) {
        Ok(endpoint) => println!("Bootstrapped to {:?}", endpoint),
        Err(e) => {
            match bootstrap_peers {
                Some(_) => {
                    println!("Failed to bootstrap from provided peers with error: {}\nSince peers \
                             were provided, this is assumed to NOT be the first node of a new \
                             network.\nExiting.", e);
                    std::env::set_exit_status(2);
                    return;
                },
                None => println!("Didn't bootstrap to an existing network - this is the first node \
                                 of a new network."),
            };
        }
    };


//    sleep_ms(200000);



    // // processing interaction till receiving termination command
    // if args.flag_speed {
    //     match args.arg_peers {
    //         Some(peers_string) => {
    //             let v: Vec<&str> = peers_string.as_str().split(',').collect();
    //             let mut endpoints = Vec::new();
    //             for iter in v.iter() {
    //                 let bootstrap_address = match SocketAddr::from_str(iter) {
    //                     Ok(addr) => addr,
    //                     Err(_) => {
    //                         println!(
    //                             "Failed to parse bootstrap peer as valid IPv4 or IPv6 address: {}",
    //                             iter);
    //                         continue
    //                     }
    //                 };
    //                 endpoints.push(bootstrap_address);
    //             }
    //             let speed: u16 = match args.arg_speed { Some(speed) => speed, _ => 100 };
    //             spawn(move || {
    //                 loop {
    //                     let mut rng = rand::thread_rng();
    //                     let length = rng.gen_range(50, speed);
    //                     let times = cmp::max(1, speed / length);
    //                     let sleep_time = cmp::max(1, 1000 / times);
    //                     for _ in 0..times {
    //                         let picked_peer = rng.gen_range(0, endpoints.len());
    //                         println!("sending a message with length of {} to {}", length,
    //                                  endpoints[picked_peer]);
    //                         let _ = connection_manager.send(Endpoint::Tcp(endpoints[picked_peer]),
    //                                         generate_random_vec_u8(length as usize));
    //                         std::thread::sleep_ms(sleep_time as u32);
    //                     }
    //                 }
    //             });
    //         },
    //         None => { println!("No peer address provided, no sending") }
    //     }
    //     let mut command = String::new();
    //     loop {
    //         let _ = io::stdin().read_line(&mut command);
    //         if command.trim() == "stop" {
    //           break;
    //         }
    //         command.clear();
    //     }
    // } else {
    let mut command = String::new();
    loop {
        command.clear();
        print_input_line();
        let _ = io::stdin().read_line(&mut command);
        let v: Vec<&str> = command.split(' ').collect();
        match v[0].trim() {
            "stop" => break,
            "send" => {
                let endpoint_address = match SocketAddr::from_str(v[1]) {
                    Ok(addr) => addr,
                    Err(_) => continue
                };
                let _ = connection_manager.send(Endpoint::Tcp(endpoint_address), v[2].to_string().into_bytes());
            },
            "connect" => {
                let endpoint_address = match SocketAddr::from_str(v[1].trim()) {
                    Ok(addr) => addr,
                    Err(_) => continue
                };
                connection_manager.connect(vec![Endpoint::Tcp(endpoint_address)]);
            }
            _ => {},
        }
    }
    // }
}
