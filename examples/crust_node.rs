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

use crust::{Endpoint, Port};
use crust::ConnectionManager;
use docopt::Docopt;
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
       crust_node -b <peer>
       crust_node -b <peer> -s <speed>

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
  arg_speed : Option<usize>,
  arg_port : Option<String>,
  flag_help : bool,
  flag_bootstrap : bool,
  flag_speed : bool,
  flag_origin : bool
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
  crust_nodes : Vec<CrustNode>
}

// simple "routing table" without any structure
impl FlatWorld {
  pub fn new(our_endpoints : Vec<Endpoint>) -> FlatWorld {
    FlatWorld {
      our_eps : our_endpoints,
      crust_nodes : Vec::with_capacity(40)
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
  let cm_eps = match cm.start_listening(vec![Port::Tcp(5483u16)]) {
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
    match args.arg_peer {
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
        println!("waiting for an input event");
        let event = cm_rx.recv();
        println!("got an input event");
        if event.is_err() {
          println!("stop listening");
          break;
        }
        match event.unwrap() {
            crust::Event::NewMessage(endpoint, bytes) => {
                println!("received from {} with a new message : {}",
                         match endpoint { Endpoint::Tcp(socket_addr) => socket_addr },
                         match String::from_utf8(bytes) { Ok(msg) => msg,
                                                          Err(_) => "unknown msg".to_string() });
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
  let mut command = String::new();
  loop {
      command.clear();
      println!("input command >");
      let _ = io::stdin().read_line(&mut command);
      match command.trim() {
          "stop" => break,
          "send" => {
              println!("input endpoint to send msg >");
              let mut endpoint_str = String::new();
              let _ = io::stdin().read_line(&mut endpoint_str);
              let endpoint_address = match SocketAddr::from_str(endpoint_str.trim()) {
                Ok(addr) => addr,
                Err(_) => continue
              };
              println!("input msg to send >");
              let mut msg = String::new();
              let _ = io::stdin().read_line(&mut msg);
              println!("sending to {} with message : {}", endpoint_address, msg);
              let _ = cm.send(Endpoint::Tcp(endpoint_address), msg.into_bytes());
          },
          "connect" => {
              println!("input endpoint to connect >");
              let mut endpoint_str = String::new();
              let _ = io::stdin().read_line(&mut endpoint_str);
              let endpoint_address = match SocketAddr::from_str(endpoint_str.trim()) {
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
