// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Example which runs a Crust node.
//! You can connect with nodes directly and exchange messages with them.
//!
//! ## Use
//!
//! 1. `cargo run --example crust_peer`
//! 2. Type `prepare-connection-info` command and press ENTER. Crust will generate your
//!    connection information and print it in JSON format.
//! 3. Repeat the steps 1 and 2 on a remote machine or on localhost but in a different terminal.
//! 4. Now you should be running Node1 and Node2 instances.
//! 5. Copy connection information from Node2 and type into Node1, e.g.
//!
//!    > connect 0 {"id":[69,179,26,91,30,37,129,181,210,61,9,134,181,74,170,154,33,63,253,237],
//!    "for_direct":["127.0.0.1:56419","192.168.1.122:56419","172.17.42.1:56419","10.0.0.1:56419",
//!    "86.100.204.140:43795"],"our_pk":{"encrypt":[240,160,65,141,35,248,81,3,221,127,142,130,113,
//!    81,191,59,223,134,106,52,250,136,111,244,158,79,18,148,32,125,87,21]}}
//!
//!    The second parameter `0` of connect command is our connection information number. Note, we
//!    can execute `prepare-connection-info` and Crust will create many instances. So this
//!    parameter specifies which one we're using. We must use a single instance per connection.
//!
//!    After you press ENTER you should be presented with a message declaring successful
//!    connection:
//!
//!    > Connected to peer UniqueId([255, 1, 11, 129, 240, 47, 25, 225, 183, 51, 93, 187, 205, 123,
//!      124, 62, 242, 136, 190, 60]) Node count: 1
//!
//! 6. Then you can exchange messages with connected peers:
//!
//!    > send 0 hello
//!
//!    The second parameter of a `send` message `0` is the connection index.
//!
//! 7. Type `stop` to exit.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]
// FIXME: `needless_pass_by_value` and `clone_on_ref_ptr` required to make no intrusive changes
// on code in the master branch
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clone_on_ref_ptr, needless_pass_by_value)
)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate unwrap;
use clap;
use crust;
use maidsafe_utilities;
use rand;
use serde_json;

use clap::{App, AppSettings, Arg, SubCommand};

use crust::{Config, ConnectionInfoResult, Uid};
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use std::cmp;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::str::FromStr;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct UniqueId([u8; 20]);
impl Uid for UniqueId {}

impl Distribution<UniqueId> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> UniqueId {
        UniqueId(rng.gen())
    }
}

type PrivConnectionInfo = crust::PrivConnectionInfo<UniqueId>;
type Service = crust::Service<UniqueId>;

fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(rand::random::<u8>());
    }
    vec
}

/// /////////////////////////////////////////////////////////////////////////////
///
/// Network
///
/// /////////////////////////////////////////////////////////////////////////////
struct Network {
    nodes: HashMap<usize, UniqueId>,
    our_connection_infos: BTreeMap<u32, PrivConnectionInfo>,
    performance_start: Instant,
    performance_interval: Duration,
    received_msgs: u32,
    received_bytes: usize,
    peer_index: usize,
    connection_info_index: u32,
}

// simple "routing table" without any structure
impl Network {
    pub fn new() -> Network {
        Network {
            nodes: HashMap::new(),
            our_connection_infos: BTreeMap::new(),
            performance_start: Instant::now(),
            performance_interval: Duration::from_secs(10),
            received_msgs: 0,
            received_bytes: 0,
            peer_index: 0,
            connection_info_index: 0,
        }
    }

    pub fn next_peer_index(&mut self) -> usize {
        let ret = self.peer_index;
        self.peer_index += 1;
        ret
    }

    pub fn next_connection_info_index(&mut self) -> u32 {
        let ret = self.connection_info_index;
        self.connection_info_index += 1;
        ret
    }

    pub fn print_connected_nodes(&self, service: &Service) {
        println!("Node count: {}", self.nodes.len());
        for (id, node) in &self.nodes {
            let status = if service.is_connected(node) {
                "Connected   "
            } else {
                "Disconnected"
            };

            println!("[{}] {} {:?}", id, status, node);
        }

        println!();
    }

    pub fn get_peer_id(&self, n: usize) -> Option<&UniqueId> {
        self.nodes.get(&n)
    }

    pub fn record_received(&mut self, msg_size: usize) {
        self.received_msgs += 1;
        self.received_bytes += msg_size;
        if self.received_msgs == 1 {
            self.performance_start = Instant::now();
        }
        if self.performance_start + self.performance_interval < Instant::now() {
            println!(
                "\nReceived {} messages with total size of {} bytes in last {} seconds.",
                self.received_msgs,
                self.received_bytes,
                self.performance_interval.as_secs()
            );
            self.received_msgs = 0;
            self.received_bytes = 0;
        }
    }
}

// If bootstrap doesn't succeed in n seconds and we're trying to run the speed
// test, then fail overall.  Otherwise, if no peer endpoints were provided and
// bootstrapping fails, assume this is OK, i.e. this is the first node of a new
// network.
fn on_time_out(timeout: Duration, flag_speed: bool) -> Sender<bool> {
    let (tx, rx) = channel();
    let _ = std::thread::spawn(move || {
        std::thread::sleep(timeout);
        match rx.try_recv() {
            Ok(true) => {}
            _ => {
                if flag_speed {
                    println!("Failed to connect to a peer.  Exiting.");
                    std::process::exit(3);
                }
                println!(
                    "Didn't bootstrap to an existing network - this may be the first node \
                     of a new network."
                );
            }
        }
    });

    tx
}

fn handle_new_peer(
    service: &Service,
    protected_network: Arc<Mutex<Network>>,
    peer_id: UniqueId,
) -> usize {
    let mut network = unwrap!(protected_network.lock());
    let peer_index = network.next_peer_index();
    let _ = network.nodes.insert(peer_index, peer_id);
    network.print_connected_nodes(service);
    peer_index
}

fn main() {
    unwrap!(maidsafe_utilities::log::init(true));

    let matches = App::new("crust_peer")
        .about(
            "The crust peer will run, using any config file it can find to \
             try and bootstrap off any provided peers.",
        )
        .arg(
            Arg::with_name("discovery-port")
                .long("discovery-port")
                .value_name("PORT")
                .help("Set the port for local network service discovery")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("speed")
                .short("s")
                .long("speed")
                .value_name("RATE")
                .help(
                    "Keep sending random data at a maximum speed of RATE bytes/second to the \
                     first connected peer.",
                )
                .takes_value(true),
        )
        .get_matches();

    // Construct Service and start listening
    let (channel_sender, channel_receiver) = channel();
    let (category_tx, category_rx) = channel();
    let (exit_tx, exit_rx) = channel();

    let (bs_sender, bs_receiver) = channel();
    let crust_event_category = ::maidsafe_utilities::event_sender::MaidSafeEventCategory::Crust;
    let event_sender = ::maidsafe_utilities::event_sender::MaidSafeObserver::new(
        channel_sender,
        crust_event_category,
        category_tx,
    );
    // TODO {{{
    // let mut config = unwrap!(::crust::read_config_file());
    let mut config = Config::default();
    // }}}

    config.service_discovery_port = if matches.is_present("discovery-port") {
        Some(unwrap!(
            unwrap!(matches.value_of("discovery-port"), "Expected <PORT>").parse(),
            "Expected number for <PORT>"
        ))
    } else {
        None
    };

    let mut service = unwrap!(Service::with_config(event_sender, config, rand::random()));
    unwrap!(service.start_listening_tcp());
    service.start_service_discovery();
    let service = Arc::new(Mutex::new(service));
    let service_cloned = service.clone();

    let network = Arc::new(Mutex::new(Network::new()));
    let network2 = network.clone();

    // Start event-handling thread
    let running_speed_test = matches.is_present("speed");

    let _joiner = maidsafe_utilities::thread::named("CrustNode event handler", move || {
        let service = service_cloned;
        let timeout = Duration::from_millis(100);
        loop {
            let it = match category_rx.recv_timeout(timeout) {
                Ok(v) => v,
                Err(RecvTimeoutError::Timeout) => {
                    if let Ok(()) = exit_rx.recv_timeout(timeout) {
                        break;
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            };
            match it {
                ::maidsafe_utilities::event_sender::MaidSafeEventCategory::Crust => {
                    if let Ok(event) = channel_receiver.try_recv() {
                        match event {
                            crust::Event::NewMessage(peer_id, _, bytes) => {
                                let message_length = bytes.len();
                                let mut network = unwrap!(network2.lock());
                                network.record_received(message_length);
                                println!(
                                    "\nReceived from {:?} message: {}",
                                    peer_id,
                                    String::from_utf8(bytes).unwrap_or_else(|_| format!(
                                        "non-UTF-8 message of {} bytes",
                                        message_length
                                    ))
                                );
                            }
                            crust::Event::ConnectionInfoPrepared(result) => {
                                let ConnectionInfoResult::<UniqueId> {
                                    result_token,
                                    result,
                                } = result;
                                let info = match result {
                                    Ok(i) => i,
                                    Err(e) => {
                                        println!("Failed to prepare connection info\ncause: {}", e);
                                        continue;
                                    }
                                };
                                println!("Prepared connection info with id {}", result_token);
                                let their_info = info.to_pub_connection_info();
                                let info_json = unwrap!(serde_json::to_string(&their_info));
                                println!("Share this info with the peer you want to connect to:");
                                println!("{}", info_json);
                                let mut network = unwrap!(network2.lock());
                                if network
                                    .our_connection_infos
                                    .insert(result_token, info)
                                    .is_some()
                                {
                                    panic!("Got the same result_token twice!");
                                };
                            }
                            crust::Event::BootstrapConnect(peer_id, addr) => {
                                println!(
                                    "\nBootstrapConnect with peer {:?} (address: <{:?}>)",
                                    peer_id, addr
                                );
                                let peer_index = handle_new_peer(
                                    &unwrap!(service.lock()),
                                    network2.clone(),
                                    peer_id,
                                );
                                let _ = bs_sender.send(peer_index);
                            }
                            crust::Event::BootstrapAccept(peer_id, _) => {
                                println!("\nBootstrapAccept with peer {:?}", peer_id);
                                let peer_index = handle_new_peer(
                                    &unwrap!(service.lock()),
                                    network2.clone(),
                                    peer_id,
                                );
                                let _ = bs_sender.send(peer_index);
                            }
                            crust::Event::ConnectSuccess(peer_id) => {
                                println!("\nConnected to peer {:?}", peer_id);
                                let _ = handle_new_peer(
                                    &unwrap!(service.lock()),
                                    network2.clone(),
                                    peer_id,
                                );
                            }
                            crust::Event::LostPeer(peer_id) => {
                                println!("\nLost connection to peer {:?}", peer_id);
                                let mut index = None;
                                {
                                    let network = unwrap!(network2.lock());
                                    for (i, id) in &network.nodes {
                                        if id == &peer_id {
                                            index = Some(*i);
                                            break;
                                        }
                                    }
                                }
                                let mut network = unwrap!(network2.lock());
                                if let Some(index) = index {
                                    let _ = unwrap!(
                                        network.nodes.remove(&index),
                                        "index should definitely be a key in this map"
                                    );
                                };
                                network.print_connected_nodes(&unwrap!(service.lock()));
                            }
                            e => {
                                println!("\nReceived event {:?} (not handled)", e);
                            }
                        }
                    } else {
                        break;
                    }
                }
                _ => unreachable!("This category should not have been fired - {:?}", it),
            }
        }
    });

    if running_speed_test {
        // Processing interaction till receiving ctrl+C
        let tx = on_time_out(Duration::from_secs(5), running_speed_test);

        // Block until we get one bootstrap connection
        let peer_index = bs_receiver.recv().unwrap_or_else(|e| {
            println!("CrustNode event handler closed; error : {}", e);
            std::process::exit(6);
        });
        let network = unwrap!(network.lock());
        let peer_id = unwrap!(network.get_peer_id(peer_index), "No such peer index");

        println!("Bootstrapped to {:?}", peer_id);

        let _ = tx.send(true); // stop timer with no error messages

        thread::sleep(Duration::from_millis(100));
        println!();

        let speed: u64 = unwrap!(
            unwrap!(
                matches.value_of("speed"),
                "Safe due to `running_speed_test` == true"
            )
            .parse(),
            "Expected number for <speed>"
        );
        let mut rng = rand::thread_rng();
        loop {
            let length = rng.gen_range(50, speed);
            let times = cmp::max(1, speed / length);
            let sleep_time = cmp::max(1, 1000 / times);
            for _ in 0..times {
                unwrap!(unwrap!(service.lock()).send(
                    peer_id,
                    generate_random_vec_u8(length as usize),
                    0,
                ));
                debug!(
                    "Sent a message with length of {} bytes to {:?}",
                    length, peer_id
                );
                std::thread::sleep(Duration::from_millis(sleep_time));
            }
        }
    } else {
        loop {
            use std::io::Write; // For flush().

            print!("> ");
            assert!(io::stdout().flush().is_ok());

            let mut command = String::new();
            assert!(io::stdin().read_line(&mut command).is_ok());

            let cmd = match parse_user_command(&command) {
                Some(cmd) => cmd,
                None => continue,
            };

            match cmd {
                UserCommand::PrepareConnectionInfo => {
                    let mut network = unwrap!(network.lock());
                    let token = network.next_connection_info_index();
                    unwrap!(service.lock()).prepare_connection_info(token);
                }
                UserCommand::Connect(our_info_index, their_info) => {
                    let mut network = unwrap!(network.lock());
                    let our_info_index = match u32::from_str(&our_info_index) {
                        Ok(info) => info,
                        Err(e) => {
                            println!("Invalid connection info index: {}", e);
                            continue;
                        }
                    };
                    let our_info = match network.our_connection_infos.remove(&our_info_index) {
                        Some(info) => info,
                        None => {
                            println!("Invalid connection info index");
                            continue;
                        }
                    };
                    let their_info = match serde_json::from_str(&their_info) {
                        Ok(info) => info,
                        Err(e) => {
                            println!("Error decoding their connection info");
                            println!("{}", e);
                            continue;
                        }
                    };
                    unwrap!(unwrap!(service.lock()).connect(our_info, their_info));
                }
                UserCommand::Send(peer_index, message) => {
                    let network = unwrap!(network.lock());
                    match network.get_peer_id(peer_index) {
                        Some(ref mut peer_id) => {
                            unwrap!(unwrap!(service.lock()).send(
                                *peer_id,
                                message.into_bytes(),
                                0,
                            ));
                        }
                        None => println!("Invalid connection #"),
                    }
                }
                UserCommand::SendAll(message) => {
                    let mut network = unwrap!(network.lock());
                    let msg = message.into_bytes();
                    for peer_id in network.nodes.values_mut() {
                        unwrap!(unwrap!(service.lock()).send(peer_id, msg.clone(), 0));
                    }
                }
                UserCommand::List => {
                    let network = unwrap!(network.lock());
                    network.print_connected_nodes(&unwrap!(service.lock()));
                }
                UserCommand::Stop => {
                    break;
                }
            }
        }
    }

    unwrap!(exit_tx.send(()));
    drop(service);
}

#[derive(PartialEq, Eq, Debug, Clone)]
enum UserCommand {
    Stop,
    PrepareConnectionInfo,
    Connect(String, String),
    Send(usize, String),
    SendAll(String),
    List,
}

fn parse_user_command(cmd: &str) -> Option<UserCommand> {
    let app = App::new("cli")
        .setting(AppSettings::NoBinaryName)
        .subcommand(
            SubCommand::with_name("prepare-connection-info").about("Prepare a connection info"),
        )
        .subcommand(
            SubCommand::with_name("connect")
                .about("Initiate a connection to the remote peer")
                .arg(
                    Arg::with_name("our-info-id")
                        .help("The ID of the connection info we gave to the peer")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("their-info")
                        .help("The connection info received from the peer")
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            SubCommand::with_name("send")
                .about("Send a string to the given peer")
                .arg(
                    Arg::with_name("peer")
                        .help("ID of a connection as listed using the `list` command")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("message")
                        .help("The text to send to the peer(s)")
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            SubCommand::with_name("send-all")
                .about("Send a string to all connections")
                .arg(
                    Arg::with_name("message")
                        .help("The text to send to the peer(s)")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("list").about("List existing connections and UDP sockets"),
        )
        .subcommand(SubCommand::with_name("stop").about("Exit the app"))
        .subcommand(SubCommand::with_name("help").about("Print this help"));
    let mut help_message = Vec::new();
    unwrap!(app.write_help(&mut help_message));
    let help_message = unwrap!(String::from_utf8(help_message));
    let matches = app.get_matches_from_safe(
        cmd.trim_end_matches(|c| c == '\r' || c == '\n')
            .split(' ')
            .collect::<Vec<_>>(),
    );

    let matches = match matches {
        Ok(v) => v,
        Err(_) => {
            println!("{}", help_message);
            return None;
        }
    };

    if matches.is_present("connect") {
        let matches = unwrap!(matches.subcommand_matches("connect"));
        let our_info_id = unwrap!(matches.value_of("our-info-id"), "Missing our_info_id");
        let their_info = unwrap!(matches.value_of("their-info"), "Missing their_info");
        Some(UserCommand::Connect(
            our_info_id.to_string(),
            their_info.to_string(),
        ))
    } else if matches.is_present("send") {
        let matches = unwrap!(matches.subcommand_matches("send"));
        let peer: usize = unwrap!(
            unwrap!(matches.value_of("peer"), "Missing peer").parse(),
            "expected number for <peer>"
        );
        let msg = unwrap!(matches.value_of("message"), "Missing message");
        Some(UserCommand::Send(peer, msg.to_string()))
    } else if matches.is_present("send-all") {
        let matches = unwrap!(matches.subcommand_matches("send-all"));
        let msg = unwrap!(matches.value_of("message"), "Missing message");
        Some(UserCommand::SendAll(msg.to_string()))
    } else if matches.is_present("prepare-connection-info") {
        Some(UserCommand::PrepareConnectionInfo)
    } else if matches.is_present("list") {
        Some(UserCommand::List)
    } else if matches.is_present("stop") {
        Some(UserCommand::Stop)
    } else if matches.is_present("help") {
        println!("{}", help_message);
        None
    } else {
        None
    }
}
