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

//! Example which runs a Crust node.

#![forbid(missing_docs, warnings)]
#![deny(bad_style, deprecated, drop_with_repr_extern, improper_ctypes, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints,
        unsafe_code, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate crust;
extern crate rustc_serialize;
extern crate docopt;
extern crate rand;
extern crate term;
extern crate time;

use docopt::Docopt;
use rand::random;
use rand::Rng;
use rustc_serialize::{Decodable, Decoder};
use std::cmp;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use std::sync::{Arc, Mutex};

use crust::{Service, Endpoint, Connection};

static USAGE: &'static str = "
Usage:
  crust_peer [options]

The crust peer will run, using any config file it can find to try and bootstrap
off any provided peers.  Locations for the config file are specified at
http://maidsafe.net/crust/master/crust/file_handler/struct.FileHandler.html#method.read_file

An example of a config file can be found at
https://github.com/maidsafe/crust/blob/master/installer/sample.config
This could be copied to the \"target/debug/examples\" directory of this project
for example (assuming a debug build) and modified to suit.

If a config file can't be located or it contains no contacts, or if connecting
to all of the peers fails, the UDP beacon will be used.

If no beacon port is specified in the config file, port 5484 will be chosen.

If no listening ports are supplied, a random port for each supported protocol
will be chosen.

Options:
  -c, --create-local-config  Tries to create a default config file in the same
                             directory as this exectable.  Won't overwrite an
                             existing file.
  -s RATE, --speed=RATE      Keep sending random data at a maximum speed of RATE
                             bytes/second to the first connected peer.
  -h, --help                 Display this help message.
";

#[derive(RustcDecodable, Debug)]
struct Args {
    flag_create_local_config: bool,
    flag_speed: Option<u64>,
    flag_help: bool,
}

// We'll use docopt to help parse the ongoing CLI commands entered by the user.
static CLI_USAGE: &'static str = "
Usage:
  cli connect <endpoint>
  cli send <peer> <message>...
  cli stop
";

#[derive(RustcDecodable, Debug)]
struct CliArgs {
    cmd_connect: bool,
    cmd_send: bool,
    cmd_stop: bool,
    arg_endpoint: Option<PeerEndpoint>,
    arg_peer: Option<usize>,
    arg_message: Vec<String>,
}

#[derive(Debug)]
struct PeerEndpoint {
    pub addr: Endpoint,
}

impl Decodable for PeerEndpoint {
    fn decode<D: Decoder>(decoder: &mut D)->Result<PeerEndpoint, D::Error> {
        let str = try!(decoder.read_str());
        if !str.ends_with(')') {
            return Err(decoder.error("Protocol missing"))
        }
        let address = match SocketAddr::from_str(&str[4 .. str.len() - 1]) {
            Ok(addr) => addr,
            Err(_) => {
                return Err(decoder.error(&format!(
                    "Could not decode {} as valid IPv4 or IPv6 address.", str)));
            },
        };
        if str.starts_with("Tcp(") {
            Ok(PeerEndpoint { addr: Endpoint::tcp(address) })
        } else if str.starts_with("Utp(") {
            Ok(PeerEndpoint { addr: Endpoint::utp(address) })
        } else {
            Err(decoder.error("Unrecognized protocol"))
        }
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

fn node_user_repr(node: &Endpoint) -> String {
    match *node {
        Endpoint::Tcp(addr) => format!("Tcp({})", addr),
        Endpoint::Utp(addr) => format!("Utp({})", addr),
    }
}

// simple "NodeInfo", without PKI
#[derive(Clone)]
struct CrustNode {
    pub connection_id: Connection,
    pub connected: bool
}

impl CrustNode {
    pub fn new(connection_id: Connection, connected: bool) -> CrustNode {
        CrustNode{
            connection_id: connection_id,
            connected: connected
        }
    }
}

struct Network {
    crust_nodes: Vec<CrustNode>,
    performance_start: time::SteadyTime,
    performance_interval: time::Duration,
    received_msgs: u32,
    received_bytes: u32
}

// simple "routing table" without any structure
impl Network {
    pub fn new() -> Network {
        Network {
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
                           .filter(|node| node.connection_id == new_node.connection_id)
                           .count() == 0 {
            self.crust_nodes.push(new_node);
            return true;
        }
        for node in self.crust_nodes.iter_mut().filter(|node| node.connection_id == new_node.connection_id) {
            node.connected = true;
        }
        return false;
    }

    pub fn drop_node(&mut self, lost_node: Connection) {
        for node in self.crust_nodes.iter_mut().filter(|node| node.connection_id == lost_node) {
            node.connected = false;
        }
    }

    pub fn print_connected_nodes(&self) {
        let connected_nodes =
            self.crust_nodes.iter().filter_map(|node|
                match node.connected {
                    true => Some(node.connection_id.clone()),
                    false => None,
                }).collect::<Vec<_>>();
        if connected_nodes.is_empty() {
            println!("No connected nodes.");
        } else {
            if connected_nodes.len() == 1 {
                println!("1 connected node:");
            } else {
                println!("{} connected nodes:", connected_nodes.len());
            }
            let mut i = 0;
            for node in &connected_nodes {
                println!("  [{}] {:?}", i, node);
                i += 1;
            }
            println!("");
        }
    }

    pub fn get(&self, n: usize) -> Option<&CrustNode> {
        self.crust_nodes.get(n)
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

// If bootstrap doesn't succeed in n seconds and we're trying to run the speed test, then fail overall.
// Otherwise, if no peer endpoints were provided and bootstrapping fails, assume this is
// OK, i.e. this is the first node of a new network.
fn on_time_out(ms: u32, flag_speed: bool) -> Sender<bool> {
    let (tx, rx) = channel();
    let _ = std::thread::spawn(move || {
        std::thread::sleep_ms(ms);
        match rx.try_recv() {
            Ok(true) => {},
            _ => {
                let mut stdout = term::stdout();
                if flag_speed {
                    stdout = red_foreground(stdout);
                    println!("Failed to connect to a peer.  Exiting.");
                    let _ = reset_foreground(stdout);
                    std::process::exit(3);
                }
                stdout = yellow_foreground(stdout);
                println!("Didn't bootstrap to an existing network - this may be the first node \
                             of a new network.");
                let _ = reset_foreground(stdout);
            },
        }
    });

    tx
}

fn create_local_config() {
    let mut stdout = term::stdout();
    let mut config_path = match ::crust::current_bin_dir() {
        Ok(path) => path,
        Err(error) => {
            stdout = red_foreground(stdout);
            println!("Failed to get config file path: {:?}", error);
            let _ = reset_foreground(stdout);
            std::process::exit(1);
        },
    };
    let mut config_name = ::crust::exe_file_stem()
                              .unwrap_or(::std::path::Path::new("unknown").to_path_buf());
    config_name.set_extension("crust.config");
    config_path.push(config_name);

    match ::std::fs::metadata(&config_path) {
        Ok(_) => {
            stdout = red_foreground(stdout);
            println!("Failed to create {:?} since it already exists.", config_path);
            let _ = reset_foreground(stdout);
        },
        Err(_) => {  // Continue if the file doesn't exist
            // This test helper function will use defaults for each `None` value.
            match ::crust::write_config_file(None, None, None, None, None) {
                Ok(file_path) => {
                    stdout = green_foreground(stdout);
                    println!("Created default config file at {:?}.", file_path);
                    let _ = reset_foreground(stdout);
                },
                Err(error) => {
                    stdout = red_foreground(stdout);
                    println!("Failed to write default config file: {:?}", error);
                    let _ = reset_foreground(stdout);
                    std::process::exit(2);
                },
            }
        },
    }
}

fn filter_ok<T>(vec: Vec<io::Result<T>>) -> Vec<T> {
    vec.into_iter().filter_map(|a|a.ok()).collect()
}

fn main() {
    match env_logger::init() {
        Ok(()) => {},
        Err(e) => println!("Error initialising logger; continuing without: {:?}", e)
    }

    let args: Args = Docopt::new(USAGE)
                            .and_then(|docopt| docopt.decode())
                            .unwrap_or_else(|error| error.exit());

    if args.flag_create_local_config {
        create_local_config()
    }

    let mut stdout = term::stdout();
    let mut stdout_copy = term::stdout();

    // Construct Service and start listening
    let (channel_sender, channel_receiver) = channel();
    let (bs_sender, bs_receiver) = channel();
    let mut service = Service::new(channel_sender).unwrap();
    let listening_ports = filter_ok(service.start_default_acceptors());
    assert!(listening_ports.len() >= 1);

    stdout = green_foreground(stdout);
    print!("Listening on ports");
    for port in &listening_ports {
        print!(" {:?}", *port);
    };
    println!("");

    stdout = reset_foreground(stdout);
    service.bootstrap();

    let network = Arc::new(Mutex::new(Network::new()));
    let network2 = network.clone();

    // Start event-handling thread
    let running_speed_test = args.flag_speed.is_some();
    let handler = match thread::Builder::new().name("CrustNode event handler".to_string())
                                              .spawn(move || {
        let mut bootstrapped = false;
        while let Ok(event) = channel_receiver.recv() {
            match event {
                crust::Event::NewMessage(connection, bytes) => {
                    stdout_copy = cyan_foreground(stdout_copy);
                    let message_length = bytes.len();
                    let mut network = network2.lock().unwrap();
                    network.record_received(message_length as u32);
                    println!("\nReceived from {} message: {}",
                             node_user_repr(&connection.peer_endpoint()),
                             String::from_utf8(bytes)
                             .unwrap_or(format!("non-UTF-8 message of {} bytes",
                                                message_length)));
                },
                crust::Event::OnConnect(connection) => {
                    stdout_copy = cyan_foreground(stdout_copy);
                    println!("\nConnected to peer at {:?}", connection.peer_endpoint());
                    let mut network = network2.lock().unwrap();
                    network.add_node(CrustNode::new(connection, true));
                    network.print_connected_nodes();
                    if !bootstrapped {
                        bootstrapped = true;
                        let _ = bs_sender.send(connection);
                    }
                },
                crust::Event::OnAccept(connection) => {
                    stdout_copy = cyan_foreground(stdout_copy);
                    println!("\nAccepted peer at {:?}", connection);
                    let mut network = network2.lock().unwrap();
                    network.add_node(CrustNode::new(connection, true));
                    network.print_connected_nodes();
                    if !bootstrapped {
                        bootstrapped = true;
                        let _ = bs_sender.send(connection);
                    }
                },
                crust::Event::LostConnection(c) => {
                    stdout_copy = yellow_foreground(stdout_copy);
                    println!("\nLost connection to peer at {:?}", c);
                    stdout_copy = cyan_foreground(stdout_copy);
                    let mut network = network2.lock().unwrap();
                    network.drop_node(c);
                    network.print_connected_nodes();
                },
                _ => {}
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
            std::process::exit(5);
        },
    };

    let tx = on_time_out(5000, running_speed_test);
    // Block until we get one bootstrap connection
    let connected_peer = bs_receiver.recv().unwrap_or_else(|e| {
        println!("CrustNode event handler closed; error : {}", e);
        std::process::exit(6);
    });

    stdout = green_foreground(stdout);
    println!("Bootstrapped to {:?}", connected_peer);
    stdout = reset_foreground(stdout);
    let _ = tx.send(true); // stop timer with no error messages

    thread::sleep_ms(100);
    println!("");

    if running_speed_test {  // Processing interaction till receiving ctrl+C
        let speed = args.flag_speed.unwrap();  // Safe due to `running_speed_test` == true
        let peer = connected_peer;
        let mut rng = rand::thread_rng();
        loop {
            let length = rng.gen_range(50, speed);
            let times = cmp::max(1, speed / length);
            let sleep_time = cmp::max(1, 1000 / times);
            for _ in 0..times {
                service.send(peer.clone(), generate_random_vec_u8(length as usize));
                debug!("Sent a message with length of {} bytes to {:?}", length, peer);
                std::thread::sleep_ms(sleep_time as u32);
            }
        }
    } else {
        let ref mut command = String::new();
        let docopt: Docopt = Docopt::new(CLI_USAGE).unwrap_or_else(|error| error.exit());
        let stdin = io::stdin();
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
                assert!(args.arg_endpoint.is_some());
                let peer = vec![args.arg_endpoint.unwrap().addr];
                service.connect(peer);
            } else if args.cmd_send {
                // docopt should ensure arg_peer and arg_message are valid
                assert!(args.arg_peer.is_some());
                assert!(!args.arg_message.is_empty());
                let peer = args.arg_peer.unwrap();
                let mut message: String = args.arg_message[0].clone();
                for i in 1..args.arg_message.len() {
                    message.push_str(" ");
                    message.push_str(&args.arg_message[i]);
                };
                let network = network.lock().unwrap();
                match network.get(peer) {
                    Some(ref node) => service.send(node.connection_id, message.clone().into_bytes()),
                    None => println!("Invalid connection #"),
                }
            } else if args.cmd_stop {
                stdout = green_foreground(stdout);
                println!("Stopped.");
                let _ = reset_foreground(stdout);
                break;
            }
        }
    }
    service.stop();
    drop(service);
    let _ = handler.join();
}
