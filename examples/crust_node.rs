// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe Software.

// String.as_str() is unstable; waiting RFC revision
// http://doc.rust-lang.org/nightly/std/string/struct.String.html#method.as_str
#![feature(convert)]

extern crate crust;
extern crate rustc_serialize;
extern crate docopt;
extern crate rand;
extern crate time;

use crust::{Endpoint, Port};
use crust::ConnectionManager;
use docopt::Docopt;
use rand::random;
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
       crust_node <port> -b <peer>
       crust_node <port> -b <peer> -s <speed>

Options:
    -h, --help        Display this help message.
    -o, --origin      Start a crust node as server, i.e. only listening on specified port.
    -b, --bootstrap   Start a crust node and bootstrap off the peer.
                      If no bootstrap node is provided beacon will be used.
    -s, --speed       Optional send data at maximum speed (bytes/second)
";

#[derive(RustcDecodable, Debug)]
struct Args {
  arg_peer : Option<String>,
  arg_speed : Option<u16>,
  arg_port : Option<String>,
  flag_help : bool,
  flag_bootstrap : bool,
  flag_speed : bool,
  flag_origin : bool
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
  pub endpoint : Endpoint,
  pub connected : bool
}

impl CrustNode {
  pub fn new(endpoint : Endpoint, connected : bool) -> CrustNode {
    CrustNode{
      endpoint : endpoint,
      connected : connected
    }
  }
  pub fn set_connected(&mut self) {self.connected = true;}
  pub fn set_disconnected(&mut self) {self.connected = false;}
}

struct FlatWorld {
  our_eps : Vec<Endpoint>,
  crust_nodes : Vec<CrustNode>,
  performance_start: time::SteadyTime,
  performance_interval: time::Duration,
  received_msgs: u32,
  received_bytes: u32
}

// simple "routing table" without any structure
impl FlatWorld {
  pub fn new(our_endpoints : Vec<Endpoint>) -> FlatWorld {
    FlatWorld {
      our_eps : our_endpoints,
      crust_nodes : Vec::with_capacity(40),
      performance_start: time::SteadyTime::now(),
      performance_interval: time::Duration::seconds(10),
      received_msgs: 0,
      received_bytes: 0
    }
  }

  // Will add node if not duplicated.  Returns true when added.
  pub fn add_node(&mut self, new_node : CrustNode) -> bool {
    if self.crust_nodes.iter()
                       .filter(|node| node.endpoint == new_node.endpoint)
                       .count() == 0 &&
       self.our_eps.iter()
                   .filter(|& our_ep| our_ep == &new_node.endpoint)
                   .count() == 0 {
      self.crust_nodes.push(new_node);
      return true;
    }
    return false;
  }

  pub fn drop_node(&mut self, lost_node : CrustNode) -> bool {
    for node in self.crust_nodes.iter_mut() {
      if node.endpoint == lost_node.endpoint {
        node.set_disconnected();
        return true;
      }
    }
    return false;
  }

  pub fn get_connected_nodes(&self) -> Vec<CrustNode> {
    self.crust_nodes.iter()
                    .filter_map(|node| if node.connected == true {
                      Some(node.clone())
                      } else {None})
                    .collect::<Vec<_>>()
  }

  pub fn get_all_nodes(&self) -> Vec<CrustNode> {
    self.crust_nodes.clone()
  }

  pub fn record_received(&mut self, msg_size : u32) {
    self.received_msgs += 1;
    self.received_bytes += msg_size;
    if self.received_msgs == 1 {
      self.performance_start = time::SteadyTime::now();
    }
    if self.performance_start + self.performance_interval < time::SteadyTime::now() {
      println!("received {} msgs with total size of {} Bytes in last 10 seconds",
               self.received_msgs, self.received_bytes);
      self.received_msgs = 0;
      self.received_bytes = 0;
    }
  }
}

fn main() {

  let args : Args = Docopt::new(USAGE)
                     .and_then(|d| d.decode())
                     .unwrap_or_else(|e| e.exit());

  if !args.flag_help { println!("{:?}", args); };  // TODO: remove; here for debug
  if args.flag_help {
    println!("{:?}", args);     // print help message
    return;
  };

  let (cm_tx, cm_rx) = channel();
  let cm = ConnectionManager::new(cm_tx);
  let mut listening_port : u16 = 5483;
  if args.arg_port.is_some() {
    let parsed_port: Option<u16> = args.arg_port.unwrap().trim().parse().ok();
    listening_port = match parsed_port { Some(port) => port, _ => 5483 };
  }
  let cm_eps = match cm.start_listening(vec![Port::Tcp(listening_port)]) {
    Ok(eps) => eps,
    Err(e) => panic!("Connection manager failed to start on arbitrary TCP port: {}", e)
  };
  assert!(cm_eps.len() > 0);
  for ep in &cm_eps {
    match *ep {
      Endpoint::Tcp(socket) => println!("Connection manager now listening on TCP socket {}", socket)
    };
  };
  let mut my_flat_world : FlatWorld = FlatWorld::new(cm_eps);

  let mut default_bootstrap = !args.flag_bootstrap;
  if args.flag_bootstrap {
    match args.arg_peer.clone() {
      Some(peer) => {
        // String.as_str() is unstable; waiting RFC revision
        // http://doc.rust-lang.org/nightly/std/string/struct.String.html#method.as_str
        let bootstrap_address = match SocketAddr::from_str(peer.as_str()) {
          Ok(addr) => addr,
          Err(_) => panic!("Failed to parse bootstrap peer as valid IPv4 or IPv6 address: {}", peer)
        };
        match cm.bootstrap(Some(vec![Endpoint::Tcp(bootstrap_address)])) {
          Ok(endpoint) =>  my_flat_world.add_node(CrustNode::new(endpoint, true)),
          Err(e) => { println!("Failed to bootstrap from provided peer: {}, with error : {}", peer, e);
                      panic!("Not resulting to default discovery of bootstrap nodes. Exiting"); }
                      // default_bootstrap = true; }
        };
      },
      None => { println!("No peer address provided, resort to default");
                default_bootstrap = true; }
    }
  }

  // resort to default bootstrapping methods
  if default_bootstrap && !args.flag_origin {
    match cm.bootstrap(None) {
      Ok(endpoint) => my_flat_world.add_node(CrustNode::new(endpoint, true)),
      Err(e) => { println!("Failed to bootstrap from default methods: {}", e);
                  panic!("Improve by keeping beacon alive. For now exiting"); }
    };
  };

  spawn(move || {
    loop {
        let event = cm_rx.recv();
        if event.is_err() {
          println!("stop listening");
          break;
        }
        match event.unwrap() {
            crust::Event::NewMessage(endpoint, bytes) => {
                // println!("received from {} with a new message : {}",
                //          match endpoint { Endpoint::Tcp(socket_addr) => socket_addr },
                //          match String::from_utf8(bytes) { Ok(msg) => msg,
                //                                           Err(_) => "unknown msg".to_string() });
                my_flat_world.record_received(bytes.len() as u32);
            },
            crust::Event::NewConnection(endpoint) => {
                println!("adding new node:{}", match endpoint { Endpoint::Tcp(socket_addr) => socket_addr });
                my_flat_world.add_node(CrustNode::new(endpoint, true));
            },
            crust::Event::LostConnection(endpoint) => {
                println!("dropping node:{}", match endpoint { Endpoint::Tcp(socket_addr) => socket_addr });
                my_flat_world.drop_node(CrustNode::new(endpoint, false));
            }
        }
    }
  });

  // processing interaction till receiving termination command
  if args.flag_speed {
      match args.arg_peer {
        Some(peer) => {
          let peer_address = match SocketAddr::from_str(peer.as_str()) {
            Ok(addr) => addr,
            Err(_) => panic!("Failed to parse peer as valid IPv4 or IPv6 address: {}", peer)
          };
          let speed : u16 = match args.arg_speed { Some(speed) => speed, _ => 100 };
          spawn(move || {
                  loop {
                    let length = cmp::max(50, cmp::min(random::<u8>() as u16, speed));
                    let times : usize = cmp::max(1, speed as usize / length as usize);
                    let sleep_time = cmp::max(1, 1000 / times);
                    for _ in 0..times {
                      println!("sending a message with length of {} to {}", length, peer_address);
                      let _ = cm.send(Endpoint::Tcp(peer_address), generate_random_vec_u8(length as usize));
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
      println!("input command ( stop | connect <Endpoint> | send <Endpoint> <Msg> )>");
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
              println!("sending to {} with message : {}", endpoint_address, v[2]);
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
