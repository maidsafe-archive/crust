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
#![feature(convert, exit_status)]

extern crate crust;
extern crate rustc_serialize;
extern crate docopt;
extern crate rand;
extern crate time;

use crust::{ConnectionManager, Endpoint, Port};
use docopt::Docopt;
use rand::random;
use rand::Rng;
use std::cmp;
use std::sync::mpsc::channel;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread::spawn;


// TODO: switching order of CL params, eg --speed x --bootstrap node
//       gives an error parsing node as usize... so order is strict for now
static USAGE: &'static str = "
Usage: crust_node -h
       crust_node -o <port>
       crust_node <port> -b <peers>
       crust_node <port> -b <peers> -s <speed>

Options:
    -h, --help        Display this help message.
    -o, --origin      Start the first crust node of a new network, i.e. only listening on the
                      specified port.
    -b, --bootstrap   Start a crust node and bootstrap off the peers.
                      If no bootstrap node is provided beacon will be used.
    -s, --speed       Optional send data at maximum speed (bytes/second)
";

// starting first node: cargo run --example crust_node -- -o 5483
// starting second node: cargo run --example crust_node -- 5783 -b 0.0.0.0:5483
// starting third node: cargo run --example crust_node -- 5784 -b 0.0.0.0:5483,0.0.0.0:5783
// starting forth node and sending message randomly to the above three nodes:
//    cargo run --example crust_node -- 5785 -b 0.0.0.0:5483,0.0.0.0:5783,0.0.0.0:5784 -s 1024


// starting first node: cargo run --example crust_node -- -o 5983
// starting second node: cargo run --example crust_node -- 5883 -b 0.0.0.0:5983
// starting third node: cargo run --example crust_node -- 5784 -b 0.0.0.0:5983,0.0.0.0:5883


#[derive(RustcDecodable, Debug)]
struct Args {
    arg_peers: Option<String>,
    arg_speed: Option<u16>,
    arg_port: Option<String>,
    flag_help: bool,
    flag_bootstrap: bool,
    flag_speed: bool,
    flag_origin: bool
}

pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
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
    pub fn set_connected(&mut self) {self.connected = true;}
    pub fn set_disconnected(&mut self) {self.connected = false;}
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
        // println!("connected nodes: {}", connected_nodes);
        if connected_nodes.len() == 1 {
            println!("connected nodes: {}", connected_nodes[0]);
        } else if connected_nodes.len() > 1 {
            print!("connected nodes: {}", connected_nodes[0]);
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
    let args: Args = Docopt::new(USAGE)
                       .and_then(|d| d.decode())
                       .unwrap_or_else(|e| e.exit());

    if args.flag_help {
        println!("{:?}", args);  // print help message
        return;
    };

    let (cm_tx, cm_rx) = channel();
    let mut my_flat_world: FlatWorld = FlatWorld::new();
    spawn(move || {
        loop {
            let event = cm_rx.recv();
            if event.is_err() {
                println!("stop listening");
                break;
            }
            match event.unwrap() {
                crust::Event::NewMessage(endpoint, bytes) => {
                    my_flat_world.record_received(bytes.len() as u32);
                    println!("received from {} with a new message: {}",
                             match endpoint { Endpoint::Tcp(socket_addr) => socket_addr },
                             match String::from_utf8(bytes) {
                                 Ok(msg) => msg,
                                 Err(_) => "unknown msg".to_string()
                             });
                },
                crust::Event::NewConnection(endpoint) => {
                    // println!("adding new node: {}", match endpoint {
                    //     Endpoint::Tcp(socket_addr) => socket_addr
                    // });
                    my_flat_world.add_node(CrustNode::new(endpoint, true));
                    my_flat_world.print_connected_nodes();
                },
                crust::Event::LostConnection(endpoint) => {
                    println!("dropping node: {}", match endpoint {
                        Endpoint::Tcp(socket_addr) => socket_addr
                    });
                    my_flat_world.drop_node(CrustNode::new(endpoint, false));
                }
            }
        }
    });

    let mut cm = ConnectionManager::new(cm_tx);
    let mut listening_port: u16 = 5483;
    if args.arg_port.is_some() {
        let parsed_port: Option<u16> = args.arg_port.unwrap().trim().parse().ok();
        listening_port = match parsed_port { Some(port) => port, _ => 5483 };
    }
    let cm_eps = match cm.start_listening(vec![Port::Tcp(listening_port)], Some(5583)) {
        Ok(eps) => eps,
        Err(e) => {
            println!("Connection manager failed to start on arbitrary TCP port: {}", e);
            std::env::set_exit_status(1);
            return;
        }
    };
    assert!(cm_eps.0.len() > 0);
    for ep in &cm_eps.0 {
        match *ep {
            Endpoint::Tcp(socket) =>
                println!("Connection manager now listening on TCP socket {}", socket)
        };
    };

    let mut default_bootstrap = !args.flag_bootstrap;
    if args.flag_bootstrap {
        match args.arg_peers.clone() {
            Some(peers_string) => {
                // String.as_str() is unstable; waiting RFC revision
                // http://doc.rust-lang.org/nightly/std/string/struct.String.html#method.as_str
                let v: Vec<&str> = peers_string.as_str().trim().split(',').collect();
                let mut endpoints = Vec::new();
                for iter in v.iter() {
                    let bootstrap_address = match SocketAddr::from_str(iter) {
                        Ok(addr) => addr,
                        Err(_) => {
                            println!(
                                "Failed to parse bootstrap peer as valid IPv4 or IPv6 address: {}",
                                iter);
                            continue
                        }
                    };
                    endpoints.push(Endpoint::Tcp(bootstrap_address));
                }
                match cm.bootstrap(Some(endpoints.clone()), Some(5583)) {
                    Ok(endpoint) => println!("bootstrapped to {} ", match endpoint {
                        Endpoint::Tcp(socket_addr) => socket_addr
                    }),
                    Err(e) => {
                        println!("Failed to bootstrap from provided peers with error: {}", e);
                        println!("Not resorting to default discovery of bootstrap nodes. Exiting");
                        std::env::set_exit_status(2);
                        return;
                    }
                                // default_bootstrap = true; }
                };
                for endpoint in endpoints.iter() {
                    std::thread::sleep_ms(5000);
                    println!("connecting to {} ",
                             match endpoint.clone() { Endpoint::Tcp(socket_addr) => socket_addr });
                    let _ = cm.connect(vec![endpoint.clone()]);
                }
            },
            None => { println!("No peer address provided, resort to default");
                      default_bootstrap = true; }
        }
    }

    // resort to default bootstrapping methods
    if default_bootstrap && !args.flag_origin {
        match cm.bootstrap(None, Some(5583)) {
            Ok(endpoint) =>  println!("bootstrapped to {} ",
                                      match endpoint { Endpoint::Tcp(socket_addr) => socket_addr }),
            Err(e) => {
                println!("Failed to bootstrap from default methods: {}", e);
                println!("Improve by keeping beacon alive. For now exiting.");
                std::env::set_exit_status(3);
                return;
            }
        };
    };

    // processing interaction till receiving termination command
    if args.flag_speed {
        match args.arg_peers {
            Some(peers_string) => {
                let v: Vec<&str> = peers_string.as_str().split(',').collect();
                let mut endpoints = Vec::new();
                for iter in v.iter() {
                    let bootstrap_address = match SocketAddr::from_str(iter) {
                        Ok(addr) => addr,
                        Err(_) => {
                            println!(
                                "Failed to parse bootstrap peer as valid IPv4 or IPv6 address: {}",
                                iter);
                            continue
                        }
                    };
                    endpoints.push(bootstrap_address);
                }
                let speed: u16 = match args.arg_speed { Some(speed) => speed, _ => 100 };
                spawn(move || {
                    loop {
                        let mut rng = rand::thread_rng();
                        let length = rng.gen_range(50, speed);
                        let times = cmp::max(1, speed / length);
                        let sleep_time = cmp::max(1, 1000 / times);
                        for _ in 0..times {
                            let picked_peer = rng.gen_range(0, endpoints.len());
                            println!("sending a message with length of {} to {}", length,
                                     endpoints[picked_peer]);
                            let _ = cm.send(Endpoint::Tcp(endpoints[picked_peer]),
                                            generate_random_vec_u8(length as usize));
                            std::thread::sleep_ms(sleep_time as u32);
                        }
                    }
                });
            },
            None => { println!("No peer address provided, no sending") }
        }
        let mut command = String::new();
        loop {
            let _ = io::stdin().read_line(&mut command);
            if command.trim() == "stop" {
              break;
            }
            command.clear();
        }
    } else {
        let mut command = String::new();
        loop {
            command.clear();
            println!("input command ( stop | connect <Endpoint> | send <Endpoint> <Msg> )  >>>");
            // stop
            // connect <Endpoint>
            // send <Endpoint> <Msg>
            let _ = io::stdin().read_line(&mut command);
            let v: Vec<&str> = command.split(' ').collect();
            match v[0].trim() {
                "stop" => break,
                "send" => {
                    let endpoint_address = match SocketAddr::from_str(v[1]) {
                        Ok(addr) => addr,
                        Err(_) => continue
                    };
                    println!("sending to {} with message: {}", endpoint_address, v[2]);
                    let _ = cm.send(Endpoint::Tcp(endpoint_address), v[2].to_string().into_bytes());
                },
                "connect" => {
                    let endpoint_address = match SocketAddr::from_str(v[1].trim()) {
                        Ok(addr) => addr,
                        Err(_) => continue
                    };
                    println!("connecting to {} ", endpoint_address);
                    let _ = cm.connect(vec![Endpoint::Tcp(endpoint_address)]);
                }
                _ => {},
            }
        }
    }
}
