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
#![deny(deprecated, drop_with_repr_extern, improper_ctypes,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
extern crate crust;
extern crate rustc_serialize;
extern crate docopt;
extern crate rand;
extern crate term;
extern crate time;
extern crate sodiumoxide;
extern crate cbor;

use docopt::Docopt;
use rand::random;
use rand::Rng;
use rustc_serialize::{Decodable, Decoder};
use std::cmp;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::io;
use std::net;
use std::str::FromStr;
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;

use crust::{Service, Protocol, Endpoint, Connection, ConnectionInfoResult,
            SocketAddr, OurConnectionInfo, TheirConnectionInfo};

use sodiumoxide::crypto::sign::ed25519::PublicKey;

static USAGE: &'static str = "
Usage:
  crust_peer [options]

The crust peer will run, using any \
                              config file it can find to try and bootstrap
off any provided \
                              peers.  Locations for the config file are specified at
\
                              http://maidsafe.net/crust/master/crust/file_handler/struct.\
                              FileHandler.html#method.read_file

An example of a config file can \
                              be found at
\
                              https://github.com/maidsafe/crust/blob/master/installer/sample.\
                              config
This could be copied to the \"target/debug/examples\" \
                              directory of this project
for example (assuming a debug build) and \
                              modified to suit.

If a config file can't be located or it contains \
                              no contacts, or if connecting
to all of the peers fails, the UDP \
                              beacon will be used.

If no beacon port is specified in the config \
                              file, port 5484 will be chosen.

If no listening ports are \
                              supplied, a random port for each supported protocol
will be chosen.

\
                              Options:
  -s RATE, --speed=RATE      Keep sending random \
                              data at a maximum speed of RATE
                             \
                              bytes/second to the first connected peer.
  -h, --help                 \
                              Display this help message.
";

const BEACON_PORT: u16 = 5484;

#[derive(RustcDecodable, Debug)]
struct Args {
    flag_speed: Option<u64>,
    flag_help: bool,
}

fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}

/// /////////////////////////////////////////////////////////////////////////////
///
/// Network
///
/// /////////////////////////////////////////////////////////////////////////////
struct Network {
    nodes: HashMap<PublicKey, Connection>,
    our_contact_infos: BTreeMap<u32, String>,
    ready_contact_infos: HashMap<String, OurConnectionInfo>,
    performance_start: time::SteadyTime,
    performance_interval: time::Duration,
    received_msgs: u32,
    received_bytes: usize,
}

// simple "routing table" without any structure
impl Network {
    pub fn new() -> Network {
        Network {
            nodes: HashMap::new(),
            our_contact_infos: BTreeMap::new(),
            ready_contact_infos: HashMap::new(),
            performance_start: time::SteadyTime::now(),
            performance_interval: time::Duration::seconds(10),
            received_msgs: 0,
            received_bytes: 0,
        }
    }

    pub fn print_connected_nodes(&self) {
        println!("Node count: {}", self.nodes.len());
        for (i, (id, node)) in self.nodes.iter().enumerate() {
            let status = if !node.is_closed() {
                "Connected   "
            } else {
                "Disconnected"
            };

            println!("    [{}] {} {:?}", i, status, id);
        }

        println!("");
    }

    pub fn remove_disconnected_nodes(&mut self) {
        let to_remove = self.nodes.iter().filter_map(|(id, node)| {
            if node.is_closed() {
                Some(id.clone())
            } else {
                None
            }
        }).collect::<Vec<_>>();
        for id in to_remove {
            let _ = self.nodes.remove(&id);
        }
    }

    pub fn get_mut(&mut self, n: usize) -> Option<&mut Connection> {
        self.nodes.iter_mut().skip(n).next().map(|(_, c)| c)
    }

    pub fn record_received(&mut self, msg_size: usize) {
        self.received_msgs += 1;
        self.received_bytes += msg_size;
        if self.received_msgs == 1 {
            self.performance_start = time::SteadyTime::now();
        }
        if self.performance_start + self.performance_interval < time::SteadyTime::now() {
            println!("\nReceived {} messages with total size of {} bytes in last {} seconds.",
                     self.received_msgs,
                     self.received_bytes,
                     self.performance_interval.num_seconds());
            self.received_msgs = 0;
            self.received_bytes = 0;
        }
    }
}

fn foreground(stdout: Option<Box<term::StdoutTerminal>>,
              colour: u16)
              -> Option<Box<term::StdoutTerminal>> {
    match stdout {
        Some(mut term) => {
            let _ = term.fg(colour);
            Some(term)
        }
        None => stdout,
    }
}

fn green_foreground(stdout: Option<Box<term::StdoutTerminal>>) -> Option<Box<term::StdoutTerminal>> {
    foreground(stdout, term::color::BRIGHT_GREEN)
}

fn yellow_foreground(stdout: Option<Box<term::StdoutTerminal>>) -> Option<Box<term::StdoutTerminal>> {
    foreground(stdout, term::color::BRIGHT_YELLOW)
}

fn red_foreground(stdout: Option<Box<term::StdoutTerminal>>) -> Option<Box<term::StdoutTerminal>> {
    foreground(stdout, term::color::BRIGHT_RED)
}

fn cyan_foreground(stdout: Option<Box<term::StdoutTerminal>>) -> Option<Box<term::StdoutTerminal>> {
    foreground(stdout, term::color::BRIGHT_CYAN)
}

fn reset_foreground(stdout: Option<Box<term::StdoutTerminal>>) -> Option<Box<term::StdoutTerminal>> {
    match stdout {
        Some(mut term) => {
            let _ = term.reset();
            Some(term)
        }
        None => stdout,
    }
}

// If bootstrap doesn't succeed in n seconds and we're trying to run the speed test, then fail overall.
// Otherwise, if no peer endpoints were provided and bootstrapping fails, assume this is
// OK, i.e. this is the first node of a new network.
fn on_time_out(timeout: Duration, flag_speed: bool) -> Sender<bool> {
    let (tx, rx) = channel();
    let _ = std::thread::spawn(move || {
        std::thread::sleep(timeout);
        match rx.try_recv() {
            Ok(true) => {}
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
            }
        }
    });

    tx
}

fn main() {
    ::maidsafe_utilities::log::init(true);

    let args: Args = Docopt::new(USAGE)
                         .and_then(|docopt| docopt.decode())
                         .unwrap_or_else(|error| error.exit());

    let mut stdout = term::stdout();
    let mut stdout_copy = term::stdout();

    // Construct Service and start listening
    let (channel_sender, channel_receiver) = channel();
    let (category_tx, category_rx) = channel();

    let (bs_sender, bs_receiver) = channel();
    let crust_event_category =
        ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent;
    let event_sender =
        ::maidsafe_utilities::event_sender::MaidSafeObserver::new(channel_sender,
                                                                  crust_event_category,
                                                                  category_tx);
    let mut service = Service::new(event_sender, BEACON_PORT).unwrap();

    let network = Arc::new(Mutex::new(Network::new()));
    let network2 = network.clone();

    // Start event-handling thread
    let running_speed_test = args.flag_speed.is_some();

    let handler = match thread::Builder::new().name("CrustNode event handler".to_string())
                                              .spawn(move || {
        let mut bootstrapped = false;
        for it in category_rx.iter() {
            match it {
                ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent => {
                    if let Ok(event) = channel_receiver.try_recv() {
                        match event {
                            crust::Event::NewMessage(connection, bytes) => {
                                stdout_copy = cyan_foreground(stdout_copy);
                                let message_length = bytes.len();
                                let mut network = network2.lock().unwrap();
                                network.record_received(message_length);
                                println!("\nReceived from {:?} message: {}",
                                         connection,
                                         String::from_utf8(bytes)
                                         .unwrap_or(format!("non-UTF-8 message of {} bytes",
                                                            message_length)));
                            },
                            crust::Event::ConnectionInfoPrepared(result) => {
                                let ConnectionInfoResult {
                                    result_token, result } = result;
                                let mut network = network2.lock().unwrap();
                                let our_file = network.our_contact_infos
                                    .remove(&result_token).unwrap();
                                let info = match result {
                                    Ok(i) => i,
                                    Err(e) => {
                                        println!("Failed to create {}\ncause: {}",
                                                 our_file, e);
                                        continue;
                                    }
                                };
                                let file = File::create(&our_file).unwrap();
                                let mut enc = cbor::Encoder::from_writer(file);
                                enc.encode(::std::iter::once(&info.to_their_connection_info())).unwrap();
                                let _ = network.ready_contact_infos.insert(our_file.clone(), info);
                                drop(enc);
                                println!("\n\"{}\" with our connection info is ready",
                                         our_file);
                            },
                            crust::Event::NewBootstrapConnection{ connection, their_pub_key } |
                            crust::Event::NewConnection{ connection: Ok(connection), their_pub_key } => {
                                stdout_copy = cyan_foreground(stdout_copy);
                                println!("\nConnected to peer at {:?}", their_pub_key);
                                let mut network = network2.lock().unwrap();
                                let _ = network.nodes.insert(their_pub_key.clone(), connection);
                                network.print_connected_nodes();
                                if !bootstrapped {
                                    bootstrapped = true;
                                    let _ = bs_sender.send(their_pub_key);
                                }
                            }
                            crust::Event::LostConnection(pub_key) => {
                                stdout_copy = yellow_foreground(stdout_copy);
                                println!("\nLost connection to peer at {:?}",
                                         pub_key);
                                stdout_copy = cyan_foreground(stdout_copy);
                                let mut network = network2.lock().unwrap();
                                let _ = network.nodes.remove(&pub_key);
                                network.print_connected_nodes();
                            }
                            e => {
                                println!("\nReceived event {:?} (not handled)", e);
                            }
                        }

                        stdout_copy = reset_foreground(stdout_copy);
                    } else {
                        break;
                    }
                },
                _ => unreachable!("This category should not have been fired - {:?}", it),
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

    if running_speed_test {
        // Processing interaction till receiving ctrl+C
        let tx = on_time_out(Duration::from_secs(5), running_speed_test);

        // Block until we get one bootstrap connection
        let connected_peer = bs_receiver.recv().unwrap_or_else(|e| {
            println!("CrustNode event handler closed; error : {}", e);
            std::process::exit(6);
        });

        stdout = green_foreground(stdout);
        println!("Bootstrapped to {:?}", connected_peer);
        let _ = reset_foreground(stdout);

        let _ = tx.send(true); // stop timer with no error messages

        thread::sleep(Duration::from_millis(100));
        println!("");

        let speed = args.flag_speed.unwrap();  // Safe due to `running_speed_test` == true
        let peer = connected_peer;
        let mut rng = rand::thread_rng();
        let mut network = network.lock().unwrap();
        loop {
            let length = rng.gen_range(50, speed);
            let times = cmp::max(1, speed / length);
            let sleep_time = cmp::max(1, 1000 / times);
            for _ in 0..times {
                network.nodes.get_mut(&peer).unwrap()
                    .send(&generate_random_vec_u8(length as usize)[..]).unwrap();
                debug!("Sent a message with length of {} bytes to {:?}",
                       length, peer);
                std::thread::sleep(Duration::from_millis(sleep_time));
            }
        }
    } else {
        print_usage();

        loop {
            use std::io::Write; // For flush().

            print!("> ");
            assert!(io::stdout().flush().is_ok());

            let mut command = String::new();
            assert!(io::stdin().read_line(&mut command).is_ok());

            let cmd = match parse_user_command(command) {
                Some(cmd) => cmd,
                None => continue,
            };

            match cmd {
                UserCommand::PrepareConnectionInfo(our_file) => {
                    let mut token = 0;
                    let mut network = network.lock().unwrap();
                    while network.our_contact_infos.contains_key(&token) {
                        token += 1;
                    }
                    let _ = network.our_contact_infos.insert(token, our_file);
                    service.prepare_connection_info(token);
                }
                UserCommand::Connect(our_file, their_file) => {
                    let mut network = network.lock().unwrap();
                    let our_info = network.ready_contact_infos.remove(&our_file)
                        .unwrap();
                    let their_file = File::open(&their_file).unwrap();
                    let their_info = cbor::Decoder::from_reader(their_file)
                        .decode::<TheirConnectionInfo>().next().unwrap().unwrap();
                    println!("Connecting to {:?}", their_info);
                    service.connect(our_info, their_info);
                }
                UserCommand::Send(peer, message) => {
                    let mut network = network.lock().unwrap();
                    match network.get_mut(peer) {
                        Some(ref mut node) => {
                            node.send(&message.into_bytes()[..]).unwrap()
                        }
                        None => println!("Invalid connection #"),
                    }
                }
                UserCommand::SendAll(message) => {
                    let mut network = network.lock().unwrap();
                    for (_, node) in network.nodes.iter_mut() {
                        node.send(&message.clone().into_bytes()[..]).unwrap();
                    }
                }
                UserCommand::List => {
                    let network = network.lock().unwrap();
                    network.print_connected_nodes();
                }
                UserCommand::Clean => {
                    let mut network = network.lock().unwrap();
                    network.remove_disconnected_nodes();
                    network.print_connected_nodes();
                }
                UserCommand::Stop => {
                    break;
                }
            }
        }
    }

    drop(service);
    assert!(handler.join().is_ok());
}

/// /////////////////////////////////////////////////////////////////////////////
///
///  Paring user commands.
///
/// /////////////////////////////////////////////////////////////////////////////
/// We'll use docopt to help parse the ongoing CLI commands entered by the user.
static CLI_USAGE: &'static str = "
Usage:
  cli prepare-connection-info <our-file>
  cli connect <our-file> <their-file>
  cli send <peer> <message>...
  cli send-all <message>...
  cli list
  cli clean
  cli stop
  cli help

";

fn print_usage() {
    static USAGE: &'static str = r#"\
# Commands:
    prepare-connection-info <our-file>            - Use existing connections to find our external
    connect <our-file> <their-file>               - Initiate a connection to the remote endpoint
    send <connection-id> <message>                - Send a string to the given connection
    send-all <message>                            - Send a string to all connections
    list                                          - List existing connections and UDP sockets
    clean                                         - Remove disconnected connections from the list
    stop                                          - Exit the app
    help                                          - Print this help

# Where
    <our-file>      - The file where we'll read/write our connection info
    <their-file>    - The file where we'll read their connection info.
    <connection-id> - ID of a connection as listed using the `list` command
"#;
    println!("{}", USAGE);
}

#[derive(RustcDecodable, Debug)]
struct CliArgs {
    cmd_prepare_connection_info: bool,
    cmd_connect: bool,
    cmd_send: bool,
    cmd_send_all: bool,
    cmd_list: bool,
    cmd_clean: bool,
    cmd_stop: bool,
    cmd_help: bool,
    arg_peer: Option<usize>,
    arg_message: Vec<String>,
    arg_our_file: Option<String>,
    arg_their_file: Option<String>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
enum UserCommand {
    Stop,
    PrepareConnectionInfo(String),
    Connect(String, String),
    Send(usize, String),
    SendAll(String),
    List,
    Clean,
}

fn parse_user_command(cmd: String) -> Option<UserCommand> {
    let docopt: Docopt = Docopt::new(CLI_USAGE).unwrap_or_else(|error| error.exit());

    let mut cmds = cmd.trim_right_matches(|c| c == '\r' || c == '\n')
                      .split(' ')
                      .collect::<Vec<_>>();

    cmds.insert(0, "cli");

    let args: CliArgs = match docopt.clone().argv(cmds.into_iter()).decode() {
        Ok(args) => args,
        Err(error) => {
            match error {
                docopt::Error::Decode(what) => println!("{}", what),
                _ => println!("Invalid command."),
            };
            return None;
        }
    };

    if args.cmd_connect {
        let our_file = args.arg_our_file.unwrap();
        let their_file = args.arg_their_file.unwrap();
        Some(UserCommand::Connect(our_file, their_file))
    } else if args.cmd_send {
        let peer = args.arg_peer.unwrap();
        let msg = args.arg_message.join(" ");
        Some(UserCommand::Send(peer, msg))
    } else if args.cmd_send_all {
        let msg = args.arg_message.join(" ");
        Some(UserCommand::SendAll(msg))
    } else if args.cmd_prepare_connection_info {
        let our_file = args.arg_our_file.unwrap();
        Some(UserCommand::PrepareConnectionInfo(our_file))
    } else if args.cmd_list {
        Some(UserCommand::List)
    } else if args.cmd_clean {
        Some(UserCommand::Clean)
    } else if args.cmd_stop {
        Some(UserCommand::Stop)
    } else if args.cmd_help {
        print_usage();
        None
    } else {
        None
    }
}

/// /////////////////////////////////////////////////////////////////////////////
///
/// Parse transport::Endpoint
///
/// /////////////////////////////////////////////////////////////////////////////
#[derive(Debug)]
struct PeerEndpoint {
    pub addr: Endpoint,
}

impl Decodable for PeerEndpoint {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<PeerEndpoint, D::Error> {
        let str = try!(decoder.read_str());
        if !str.ends_with(')') {
            return Err(decoder.error("Protocol missing"));
        }
        let address = match net::SocketAddr::from_str(&str[4..str.len() - 1]) {
            Ok(addr) => SocketAddr(addr),
            Err(_) => {
                return Err(decoder.error(&format!("Could not decode {} as valid IPv4 or IPv6 \
                                                   address.",
                                                  str)));
            }
        };
        if str.starts_with("Tcp(") {
            Ok(PeerEndpoint { addr: Endpoint::from_socket_addr(Protocol::Tcp, address) })
        } else if str.starts_with("Utp(") {
            Ok(PeerEndpoint { addr: Endpoint::from_socket_addr(Protocol::Utp, address) })
        } else {
            Err(decoder.error("Unrecognized protocol"))
        }
    }
}

// /////////////////////////////////////////////////////////////////////////////
