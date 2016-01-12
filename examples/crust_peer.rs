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

use docopt::Docopt;
use rand::random;
use rand::Rng;
use rustc_serialize::{Decodable, Decoder};
use std::cmp;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::io;
use std::net::{UdpSocket, SocketAddr};
use std::collections::HashSet;
use std::str::FromStr;
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crust::{Service, Endpoint, Connection, Port};

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
                             directory as this executable.  Won't overwrite an
                             existing file.
  -s RATE, --speed=RATE      Keep sending random data at a maximum speed of RATE
                             bytes/second to the first connected peer.
  -h, --help                 Display this help message.
";

const BEACON_PORT: u16 = 5484;

#[derive(RustcDecodable, Debug)]
struct Args {
    flag_create_local_config: bool,
    flag_speed: Option<u64>,
    flag_help: bool,
}

fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size { vec.push(random::<u8>()); }
    vec
}

fn node_user_repr(node: &Endpoint) -> String {
    match *node {
        Endpoint::Tcp(addr) => format!("Tcp({})", addr),
        Endpoint::Utp(addr) => format!("Utp({})", addr),
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// CrustNode
//
////////////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////////////
//
// UdpData
//
////////////////////////////////////////////////////////////////////////////////
struct UdpData {
    stopped:            Arc<Mutex<bool>>,
    socket:             UdpSocket,
    external_endpoints: HashSet<SocketAddr>,
    receiver_join_handle: Option<thread::JoinHandle<()>>,
}

impl UdpData {
    pub fn new(socket: UdpSocket, ext_eps: HashSet<SocketAddr>) -> UdpData {
        use ::std::io::ErrorKind::{TimedOut, WouldBlock, Interrupted};

        let stopped = Arc::new(Mutex::new(false));
        let stopped_copy = stopped.clone();
        let socket_copy  = socket.try_clone().unwrap();

        let join_handle = thread::spawn(move || {
            let mut buf = [0u8; 256];
            let timeout = ::std::time::Duration::from_millis(100);
            assert!(socket.set_read_timeout(Some(timeout)).is_ok());
            loop {
                {
                    let stopped = stopped.lock().unwrap();
                    if *stopped { break; }
                }

                match socket.recv_from(&mut buf) {
                    Ok(_x)   => {
                        println!("UdpSocket received data");
                    },
                    Err(e)  => match e.kind() {
                        TimedOut | WouldBlock => continue,
                        Interrupted => (),
                        _   => break,
                    },
                }
            }
        });

        UdpData {
            stopped: stopped_copy,
            socket: socket_copy,
            external_endpoints: ext_eps,
            receiver_join_handle: Some(join_handle),
        }
    }

    pub fn send_to(&self, destination: SocketAddr) {
        let buf = [0u8; 256];
        assert!(self.socket.send_to(&buf, destination).is_ok());
    }
}

impl Drop for UdpData {
    fn drop(&mut self) {
        {
            let mut stopped = self.stopped.lock().unwrap();
            *stopped = true;
        }
        let join_handle = self.receiver_join_handle.take();
        assert!(join_handle.unwrap().join().is_ok());
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// Network
//
////////////////////////////////////////////////////////////////////////////////
struct Network {
    crust_nodes:          Vec<CrustNode>,
    udp_data:             Vec<UdpData>,
    performance_start:    time::SteadyTime,
    performance_interval: time::Duration,
    received_msgs:        u32,
    received_bytes:       usize
}

// simple "routing table" without any structure
impl Network {
    pub fn new() -> Network {
        Network {
            crust_nodes:          Vec::new(),
            udp_data:             Vec::new(),
            performance_start:    time::SteadyTime::now(),
            performance_interval: time::Duration::seconds(10),
            received_msgs:        0,
            received_bytes:       0
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

    pub fn release_udp_socket(&mut self, id: usize) -> Option<UdpSocket> {
        if id >= self.udp_data.len() {
            return None;
        }
        let d = self.udp_data.remove(id);
        d.socket.try_clone().ok()

    }

    pub fn drop_node(&mut self, lost_node: Connection) {
        for node in self.crust_nodes.iter_mut().filter(|node| node.connection_id == lost_node) {
            node.connected = false;
        }
    }

    pub fn print_connected_nodes(&self) {
        println!("Node count: {}", self.crust_nodes.len());
        let mut i = 0;
        for node in self.crust_nodes.iter() {
            let status = if node.connected { "Connected   " }
                                      else { "Disconnected" };

            println!("    [{}] {} {:?}", i, status, node.connection_id);
            i += 1;
        }

        println!("\nUdp socket count: {}", self.udp_data.len());
        let mut i = 0;
        for data in &self.udp_data {
            println!("    [{}] {:?} {:?}",
                     i,
                     data.socket.local_addr().unwrap(),
                     data.external_endpoints);
            i += 1;
        }

        println!("");
    }

    pub fn remove_disconnected_nodes(&mut self) {
        self.crust_nodes.retain(|node|node.connected);
    }

    pub fn get(&self, n: usize) -> Option<&CrustNode> {
        self.crust_nodes.get(n)
    }

    pub fn get_udp(&self, n: usize) -> Option<&UdpData> {
        self.udp_data.get(n)
    }

    pub fn get_all(&self) -> &Vec<CrustNode> {
        &self.crust_nodes
    }

    pub fn record_received(&mut self, msg_size: usize) {
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
fn on_time_out(timeout: Duration, flag_speed: bool) -> Sender<bool> {
    let (tx, rx) = channel();
    let _ = std::thread::spawn(move || {
        std::thread::sleep(timeout);
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

fn create_local_config() -> Result<(), crust::error::Error> {
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
    let mut config_name = try!(::crust::exe_file_stem());
    config_name.push(".crust.config");
    config_path.push(config_name);

    match ::std::fs::metadata(&config_path) {
        Ok(_) => {
            stdout = red_foreground(stdout);
            println!("Failed to create {:?} since it already exists.", config_path);
            let _ = reset_foreground(stdout);
        },
        Err(_) => {  // Continue if the file doesn't exist
            // This test helper function will use defaults for each `None` value.
            match ::crust::write_config_file(None) {
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
    };
    Ok(())
}

fn filter_ok<T>(vec: Vec<io::Result<T>>) -> Vec<T> {
    vec.into_iter().filter_map(|a|a.ok()).collect()
}

fn main() {
    ::maidsafe_utilities::log::init(true);

    let args: Args = Docopt::new(USAGE)
                            .and_then(|docopt| docopt.decode())
                            .unwrap_or_else(|error| error.exit());

    if args.flag_create_local_config {
        unwrap_result!(create_local_config());
    }

    let mut stdout = term::stdout();
    let mut stdout_copy = term::stdout();

    // Construct Service and start listening
    let (channel_sender, channel_receiver) = channel();
    let (category_tx, category_rx) = channel();

    let (bs_sender, bs_receiver) = channel();
    let crust_event_category = ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent;
    let event_sender = ::maidsafe_utilities::event_sender::MaidSafeObserver::new(channel_sender,
                                                                                 crust_event_category,
                                                                                 category_tx);
    let mut service = Service::new(event_sender).unwrap();
    let listening_ports = filter_ok(vec![service.start_accepting(Port::Tcp(0))]);
    assert!(listening_ports.len() >= 1);
    let _ = service.start_beacon(BEACON_PORT);

    stdout = green_foreground(stdout);
    print!("Listening on ports");
    for port in &listening_ports {
        print!(" {:?}", *port);
    };
    println!("");

    stdout = reset_foreground(stdout);
    service.bootstrap(0, Some(BEACON_PORT));

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
                                println!("\nReceived from {} message: {}",
                                         node_user_repr(&connection.peer_endpoint()),
                                         String::from_utf8(bytes)
                                         .unwrap_or(format!("non-UTF-8 message of {} bytes",
                                                            message_length)));
                            },
                            crust::Event::OnConnect(Ok((_, connection)), _) |
                            crust::Event::OnRendezvousConnect(Ok((_, connection)), _) => {
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
                            crust::Event::OnAccept(_, connection) => {
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
                            crust::Event::OnUdpSocketMapped(content) => {
                                match content.result {
                                    Ok((socket, ext_endpoints)) => {
                                        println!("UdpSocket mapped: {} {:?}",
                                                 content.result_token, ext_endpoints);

                                        let mut network = network2.lock().unwrap();
                                        network.udp_data.push(UdpData::new(socket, ext_endpoints));
                                        network.print_connected_nodes();
                                    },
                                    Err(what) => {
                                        println!("UdpSocket mapping failed: {} {:?}",
                                                 content.result_token, what);
                                    },
                                }
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

    if running_speed_test {  // Processing interaction till receiving ctrl+C
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
        loop {
            let length = rng.gen_range(50, speed);
            let times = cmp::max(1, speed / length);
            let sleep_time = cmp::max(1, 1000 / times);
            for _ in 0..times {
                service.send(peer.clone(), generate_random_vec_u8(length as usize));
                debug!("Sent a message with length of {} bytes to {:?}", length, peer);
                std::thread::sleep(Duration::from_millis(sleep_time));
            }
        }
    } else {
        print_usage();

        loop {
            use ::std::io::Write; // For flush().

            print!("> ");
            assert!(io::stdout().flush().is_ok());

            let mut command = String::new();
            assert!(io::stdin().read_line(&mut command).is_ok());

            let cmd = match parse_user_command(command) {
                Some(cmd) => cmd,
                None => continue,
            };

            match cmd {
                UserCommand::Connect(ep) => {
                    println!("Connecting to {:?}", ep);
                    service.connect(0, vec![ep]);
                },
                UserCommand::ConnectRendezvous(udp_id, endpoint) => {
                    let mut network = network.lock().unwrap();
                    let socket = match network.release_udp_socket(udp_id) {
                        Some(socket) => socket,
                        None => {
                            println!("No such UDP socket #{}", udp_id);
                            continue;
                        }
                    };
                    println!("ConnectingRendezvous with {} to {:?}", udp_id, endpoint);
                    service.rendezvous_connect(socket, 0, endpoint);
                },
                UserCommand::Send(peer, message) => {
                    let network = network.lock().unwrap();
                    match network.get(peer) {
                        Some(ref node) => service.send(node.connection_id,
                                                       message.into_bytes()),
                        None => println!("Invalid connection #"),
                    }
                },
                UserCommand::SendUdp(peer, dst, _message) => {
                    let network = network.lock().unwrap();
                    match network.get_udp(peer) {
                        Some(ref udp) => udp.send_to(dst),
                        None => println!("Invalid udp #"),
                    }
                },
                UserCommand::SendAll(message) => {
                    let network = network.lock().unwrap();
                    for node in network.get_all() {
                        service.send(node.connection_id, message.clone().into_bytes());
                    }
                },
                UserCommand::Punch(peer, dst) => {
                    let network = network.lock().unwrap();
                    match network.get_udp(peer) {
                        Some(ref udp) => {
                            let socket = udp.socket.try_clone().unwrap();
                            service.udp_punch_hole(0, socket, None, dst);
                        },
                        None => println!("Invalid udp #"),
                    }
                },
                UserCommand::Map => {
                    service.get_mapped_udp_socket(0);
                },
                UserCommand::List => {
                    let network = network.lock().unwrap();
                    network.print_connected_nodes();
                },
                UserCommand::Clean => {
                    let mut network = network.lock().unwrap();
                    network.remove_disconnected_nodes();
                    network.print_connected_nodes();
                },
                UserCommand::Stop => {
                    break;
                },
            }
        }
    }

    drop(service);

    assert!(handler.join().is_ok());
}

////////////////////////////////////////////////////////////////////////////////
//
//  Paring user commands.
//
////////////////////////////////////////////////////////////////////////////////
// We'll use docopt to help parse the ongoing CLI commands entered by the user.
static CLI_USAGE: &'static str = "
Usage:
  cli connect <endpoint>
  cli connect-rendezvous <peer> <endpoint>
  cli send <peer> <message>...
  cli send-udp <peer> <destination> <message>...
  cli send-all <message>...
  cli map
  cli punch <peer> <destination>
  cli list
  cli clean
  cli stop
  cli help

";

fn print_usage() {
    static USAGE: &'static str = r#"\
# Commands:
    connect <endpoint>                            - Initiate a connection to the remote endpoint
    connect-rendezvous <udp-socket-id> <endpoint> - As above, but using rendezvous connect
    send <connection-id> <message>                - Send a string to the given connection
    send-udp <udp-socket-id> <message>            - E.g. send-udp 0 foo bar
    send-all <message>                            - Send a string to all connections
    map                                           - Use existing connections to find our external
                                                    IP address.  Also creates a UDP socket.
    punch <udp-socket-id> <socketaddr>            - UDP hole punch with given socket to the given
                                                    destination
    list                                          - List existing connections and UDP sockets
    clean                                         - Remove disconnected connections from the list
    stop                                          - Exit the app
    help                                          - Print this help

# Where
    <endpoint>      - Specifies transport and socket address.  Its form is
                      [Tcp|Utp](a.b.c.d:p)
                      E.g. Tcp(192.168.0.1:5483)
    <udp-socket-id> - ID of a UDP socket as listed using the `list` command
    <connection-id> - ID of a connection as listed using the `list` command
    <socketaddr>    - IP address and port.  E.g. 192.168.0.1:5483
"#;
    println!("{}", USAGE);
}

#[derive(RustcDecodable, Debug)]
struct CliArgs {
    cmd_connect:            bool,
    cmd_connect_rendezvous: bool,
    cmd_send:               bool,
    cmd_send_udp:           bool,
    cmd_send_all:           bool,
    cmd_map:                bool,
    cmd_punch:              bool,
    cmd_list:               bool,
    cmd_clean:              bool,
    cmd_stop:               bool,
    cmd_help:               bool,
    arg_endpoint:           Option<PeerEndpoint>,
    arg_destination:        Option<::crust::SocketAddrW>,
    arg_peer:               Option<usize>,
    arg_message:            Vec<String>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
enum UserCommand {
    Stop,
    Connect(Endpoint),
    ConnectRendezvous(usize, Endpoint),
    Send(usize, String),
    SendUdp(usize, SocketAddr, String),
    SendAll(String),
    Punch(usize, SocketAddr),
    List,
    Clean,
    Map,
}

fn parse_user_command(cmd : String) -> Option<UserCommand> {
    let docopt: Docopt = Docopt::new(CLI_USAGE)
                         .unwrap_or_else(|error| error.exit());

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
        },
    };

    if args.cmd_connect {
        let peer = args.arg_endpoint.unwrap().addr;
        Some(UserCommand::Connect(peer))
    } else if args.cmd_connect_rendezvous {
        let peer = args.arg_peer.unwrap();
        let endpoint = args.arg_endpoint.unwrap().addr;
        Some(UserCommand::ConnectRendezvous(peer, endpoint))
    } else if args.cmd_send {
        let peer = args.arg_peer.unwrap();
        let msg  = args.arg_message.join(" ");
        Some(UserCommand::Send(peer, msg))
    } else if args.cmd_send_udp {
        let peer = args.arg_peer.unwrap();
        let dst  = args.arg_destination.unwrap().0;
        let msg  = args.arg_message.join(" ");
        Some(UserCommand::SendUdp(peer, dst, msg))
    } else if args.cmd_send_all {
        let msg  = args.arg_message.join(" ");
        Some(UserCommand::SendAll(msg))
    } else if args.cmd_map {
        Some(UserCommand::Map)
    } else if args.cmd_punch {
        let peer = args.arg_peer.unwrap();
        let dst  = args.arg_destination.unwrap().0;
        Some(UserCommand::Punch(peer, dst))
    } else if args.cmd_list {
        Some(UserCommand::List)
    } else if args.cmd_clean {
        Some(UserCommand::Clean)
    } else if args.cmd_stop {
        Some(UserCommand::Stop)
    } else if args.cmd_help {
        print_usage();
        None
    }
    else {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// Parse transport::Endpoint
//
////////////////////////////////////////////////////////////////////////////////

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

////////////////////////////////////////////////////////////////////////////////
