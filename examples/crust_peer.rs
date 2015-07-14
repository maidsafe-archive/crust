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
#![feature(convert, core)]
#![forbid(warnings)]
#![deny(bad_style, deprecated, drop_with_repr_extern, improper_ctypes, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints,
        unsafe_code, unsigned_negation, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

extern crate core;
extern crate crust;
extern crate rustc_serialize;
extern crate docopt;
extern crate rand;
extern crate term;
extern crate time;
extern crate tempdir;

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
use std::thread;
use std::path::PathBuf;
use tempdir::TempDir;

use crust::{ConnectionManager, Endpoint, Port, write_config_file};

static USAGE: &'static str = "
Usage:
  crust_peer [options] [<peer>...]

The crust peer will try and bootstrap off one of the peers if any are provided.
If none are provided, or if connecting to any of the peers fails, the UDP beacon
will be used. If no beacon port is specified in the options, then port 9999 will
be chosen. If no listening port is supplied, a random port for each supported
protocol will be chosen.

Options:
  -t PORT, --tcp-port=PORT  Start listening on the specified TCP port.
  -b PORT, --beacon=PORT    Set the beacon port.  If the node can, it will
                            listen for UDP broadcasts on this port.  If
                            bootstrapping using provided contacts or the cached
                            contacts fails, the node will broadcast to the
                            beacon port in an attempt to connect to a peer on
                            the same LAN.
  -c CONF, --config=CONF    Use the specified config file to set the configuration
  -s RATE, --speed=RATE     Keep sending random data at a maximum speed of RATE
                            bytes/second to the first connected peer.
  -h, --help                Display this help message.
";

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_peer: Vec<PeerEndpoint>,
    flag_tcp_port: Option<u16>,
    flag_beacon: Option<u16>,
    flag_config: Option<String>,
    flag_speed: Option<u64>,
    flag_help: bool,
}

// We'll use docopt to help parse the ongoing CLI commands entered by the user.
static CLI_USAGE: &'static str = "
Usage:
  cli connect <peer>
  cli send <peer> <message>...
  cli stop
";

#[derive(RustcDecodable, Debug)]
struct CliArgs {
    cmd_connect: bool,
    cmd_send: bool,
    cmd_stop: bool,
    arg_peer: Option<PeerEndpoint>,
    arg_message: Vec<String>,
}

#[derive(Debug)]
enum PeerEndpoint {
    Tcp(SocketAddr),
}

impl Decodable for PeerEndpoint {
    fn decode<D: Decoder>(decoder: &mut D)->Result<PeerEndpoint, D::Error> {
        let str = try!(decoder.read_str());
        let address = match SocketAddr::from_str(&str) {
            Ok(addr) => addr,
            Err(_) => {
                return Err(decoder.error(format!(
                    "Could not decode {} as valid IPv4 or IPv6 address.", str).as_str()));
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
            node.connected = true;
        }
        return false;
    }

    pub fn drop_node(&mut self, lost_node: CrustNode) {
        for node in self.crust_nodes.iter_mut().filter(|node| node.endpoint == lost_node.endpoint) {
            node.connected = false;
        }
    }

    pub fn print_connected_nodes(&self) {
        let connected_nodes =
            self.crust_nodes.iter().filter_map(|node|
                match node.connected {
                    true => Some(node.endpoint.clone()),
                    false => None,
                }).collect::<Vec<_>>();
        if connected_nodes.is_empty() {
            println!("No connected nodes.");
        } else {
            if connected_nodes.len() == 1 {
                print!("1 connected node:");
            } else {
                print!("{} connected nodes:", connected_nodes.len());
            }
            for i in 0..connected_nodes.len() {
                print!(" {:?}", connected_nodes[i]);
            }
            println!("");
        }
    }

    pub fn record_received(&mut self, msg_size: u32) {
        self.received_msgs += 1;
        self.received_bytes += msg_size;
        if self.received_msgs == 1 {
            self.performance_start = time::SteadyTime::now();
        }
        if self.performance_start + self.performance_interval < time::SteadyTime::now() {
            println!("\nReceived {} messages with total size of {} bytes in last {} seconds.",
                     self.received_msgs, self.received_bytes, self.performance_interval.num_seconds());
            self.received_msgs = 0;
            self.received_bytes = 0;
        }
    }
}

fn foreground(stdout: Option<Box<term::StdoutTerminal>>, colour: u16) ->
        Option<Box<term::StdoutTerminal>> {
    match stdout {
        Some(mut term) => {
            let _ = term.fg(colour);
            Some(term)
        },
        None => stdout,
    }
}

fn green_foreground(stdout: Option<Box<term::StdoutTerminal>>) ->
        Option<Box<term::StdoutTerminal>> {
    foreground(stdout, term::color::BRIGHT_GREEN)
}

fn yellow_foreground(stdout: Option<Box<term::StdoutTerminal>>) ->
        Option<Box<term::StdoutTerminal>> {
    foreground(stdout, term::color::BRIGHT_YELLOW)
}

fn red_foreground(stdout: Option<Box<term::StdoutTerminal>>) ->
        Option<Box<term::StdoutTerminal>> {
    foreground(stdout, term::color::BRIGHT_RED)
}

fn cyan_foreground(stdout: Option<Box<term::StdoutTerminal>>) ->
        Option<Box<term::StdoutTerminal>> {
    foreground(stdout, term::color::BRIGHT_CYAN)
}

fn reset_foreground(stdout: Option<Box<term::StdoutTerminal>>) ->
        Option<Box<term::StdoutTerminal>> {
    match stdout {
        Some(mut term) => {
            let _ = term.reset();
            Some(term)
        },
        None => stdout,
    }
}

// TODO update to take listening port once api is updated
fn make_temp_config(beacon_port: Option<u16>, tcp_port: Option<u16>) -> (PathBuf, TempDir) {
    let temp_dir = TempDir::new("crust_peer").unwrap();
    let mut config_file_path = temp_dir.path().to_path_buf();
    config_file_path.push("crust_peer.config");

    let _ = write_config_file(Some(config_file_path.clone()),
                              Some(vec![Port::Tcp(tcp_port.unwrap_or(0u16)).clone()]),
                              None,
                              None,
                              beacon_port,
                             ).unwrap();
    (config_file_path, temp_dir)
}

fn main() {
    let args: Args = Docopt::new(USAGE)
                            .and_then(|docopt| docopt.decode())
                            .unwrap_or_else(|error| error.exit());

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

    let mut stdout = term::stdout();
    let mut stdout_copy = term::stdout();

    let (config_path, _tempdir) = match args.flag_config {
        Some(path_str) => {(PathBuf::from(path_str), None)},
        None => {
            let (path, tempdir) = make_temp_config(args.flag_beacon, args.flag_tcp_port);
            (path, Some(tempdir))
        }
    };

    // Construct ConnectionManager and start listening
    let (channel_sender, channel_receiver) = channel();
    let mut connection_manager = ConnectionManager::new(channel_sender, Some(config_path));
    stdout = green_foreground(stdout);
    let listening_endpoints = match connection_manager.start_listening2() {
        Ok(endpoints) => endpoints,
        Err(e) => {
            println!("Connection manager failed to start listening: {}", e);
            std::process::exit(1);
        }
    };
    print!("Listening for new connections on ");
    for endpoint in &listening_endpoints {
        print!("{:?}, ", *endpoint);
    };

    stdout = reset_foreground(stdout);

    // Try to bootstrap.  If this fails and we're trying to run the speed test, then fail overall.
    // Otherwise, if no peer endpoints were provided and bootstrapping fails, assume this is
    // OK, i.e. this is the first node of a new network.
    let connected_peer = match connection_manager.bootstrap(bootstrap_peers.clone(), None) {
        Ok(endpoint) => {
            stdout = green_foreground(stdout);
            println!("Bootstrapped to {:?}", endpoint);
            stdout = reset_foreground(stdout);
            Some(endpoint)
        },
        Err(e) => {
            if args.flag_speed.is_some() {
                stdout = red_foreground(stdout);
                println!("Failed to connect to a peer.  Exiting.");
                let _ = reset_foreground(stdout);
                std::process::exit(2);
            };
            match bootstrap_peers {
                Some(_) => {
                    stdout = red_foreground(stdout);
                    println!("Failed to bootstrap from provided peers with error: {}\nSince peers \
                             were provided, this is assumed to NOT be the first node of a new \
                             network.\nExiting.", e);
                    let _ = reset_foreground(stdout);
                    std::process::exit(3);
                },
                None => {
                    stdout = yellow_foreground(stdout);
                    println!("Didn't bootstrap to an existing network - this is the first node \
                                 of a new network.");
                    stdout = reset_foreground(stdout);
                    None
                },
            }
        },
    };

    // Start event-handling thread
    let running_speed_test = args.flag_speed.is_some();
    let handler = match thread::Builder::new().name("CrustNode event handler".to_string())
                                              .spawn(move || {
        let mut my_flat_world: FlatWorld = FlatWorld::new();
        while let Ok(event) = channel_receiver.recv() {
            match event {
                crust::Event::NewMessage(endpoint, bytes) => {
                    stdout_copy = cyan_foreground(stdout_copy);
                    let message_length = bytes.len();
                    my_flat_world.record_received(message_length as u32);
                    println!("\nReceived from {:?} message: {}", endpoint,
                             String::from_utf8(bytes)
                             .unwrap_or(format!("non-UTF-8 message of {} bytes",
                                                message_length)));
                },
                crust::Event::NewConnection(endpoint) => {
                    stdout_copy = cyan_foreground(stdout_copy);
                    println!("\nConnected to peer at {:?}", endpoint);
                    my_flat_world.add_node(CrustNode::new(endpoint, true));
                    my_flat_world.print_connected_nodes();
                },
                crust::Event::LostConnection(endpoint) => {
                    stdout_copy = yellow_foreground(stdout_copy);
                    println!("\nLost connection to peer at {:?}", endpoint);
                    stdout_copy = cyan_foreground(stdout_copy);
                    my_flat_world.drop_node(CrustNode::new(endpoint, false));
                    my_flat_world.print_connected_nodes();
                },
                crust::Event::NewBootstrapConnection(_) => {}
            }
            stdout_copy = reset_foreground(stdout_copy);
            if !running_speed_test {
                print_input_line();
            }
        }
    }) {
        Ok(join_handle) => join_handle,
        Err(e) => {
            stdout = red_foreground(stdout);
            println!("Failed to start event-handling thread: {}", e);
            let _ = reset_foreground(stdout);
            std::process::exit(4);
        },
    };

    thread::sleep_ms(100);
    println!("");

    if running_speed_test {  // Processing interaction till receiving ctrl+C
        let speed = args.flag_speed.unwrap();  // Safe due to `running_speed_test` == true
        let peer = connected_peer.unwrap();  // Safe due to checks above
        let mut rng = rand::thread_rng();
        loop {
            let length = rng.gen_range(50, speed);
            let times = cmp::max(1, speed / length);
            let sleep_time = cmp::max(1, 1000 / times);
            for _ in 0..times {
                match connection_manager.send(peer.clone(),
                                              generate_random_vec_u8(length as usize)) {
                    Ok(()) => println!("Sent a message with length of {} bytes to {:?}", length,
                                       peer),
                    Err(_) => {
                        stdout = red_foreground(stdout);
                        println!("Lost connection to peer.  Exiting.");
                        let _ = reset_foreground(stdout);
                        return;
                    },
                };
                std::thread::sleep_ms(sleep_time as u32);
            }
        }
    } else {
        let ref mut command = String::new();
        let docopt: Docopt = Docopt::new(CLI_USAGE).unwrap_or_else(|error| error.exit());
        let mut stdin = io::stdin();
        loop {
            command.clear();
            print_input_line();
            let _ = stdin.read_line(command);
            let x: &[_] = &['\r', '\n'];
            let mut raw_args: Vec<&str> = command.trim_right_matches(x).split(' ').collect();
            raw_args.insert(0, "cli");
            let args: CliArgs = match docopt.clone().argv(raw_args.into_iter()).decode() {
                Ok(args) => args,
                Err(error) => {
                    match error {
                        docopt::Error::Decode(what) => println!("{}", what),
                        _ => println!("Invalid command."),
                    };
                    continue
                },
            };

            if args.cmd_connect {
                // docopt should ensure arg_peer is valid
                assert!(args.arg_peer.is_some());
                let peer = vec![Endpoint::Tcp(match args.arg_peer.unwrap() {
                    PeerEndpoint::Tcp(address) => address,
                })];
                connection_manager.connect(peer);
            } else if args.cmd_send {
                // docopt should ensure arg_peer and arg_message are valid
                assert!(args.arg_peer.is_some());
                assert!(!args.arg_message.is_empty());
                let peer = Endpoint::Tcp(match args.arg_peer.unwrap() {
                    PeerEndpoint::Tcp(address) => address,
                });
                let mut message: String = args.arg_message[0].clone();
                for i in 1..args.arg_message.len() {
                    message.push_str(" ");
                    message.push_str(args.arg_message[i].as_str());
                };
                match connection_manager.send(peer.clone(), message.clone().into_bytes()) {
                    Ok(()) => {
                        stdout = green_foreground(stdout);
                        println!("Successfully sent \"{}\" to {:?}", message, peer);
                        stdout = reset_foreground(stdout)
                    },
                    Err(error) => {
                        match error.kind() {
                            io::ErrorKind::NotConnected => {
                                stdout = yellow_foreground(stdout);
                                println!("Failed to send: we have no connection to {:?}", peer);
                                stdout = reset_foreground(stdout)
                            },
                            io::ErrorKind::BrokenPipe => {
                                stdout = yellow_foreground(stdout);
                                println!("Failed to send to {:?}: internal channel error.", peer);
                                stdout = reset_foreground(stdout)
                            },
                            _ => {
                                stdout = yellow_foreground(stdout);
                                println!("Failed to send to {:?}: unexpected error.", peer);
                                stdout = reset_foreground(stdout)
                            },
                        }
                    },
                }
            } else if args.cmd_stop {
                stdout = green_foreground(stdout);
                println!("Stopped.");
                let _ = reset_foreground(stdout);
                break;
            }
        }
    }
    connection_manager.stop();
    drop(connection_manager);
    let _ = handler.join();
}
