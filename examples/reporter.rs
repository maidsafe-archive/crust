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

//! Example for testing direct connections between nodes.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]

#[macro_use]
extern crate maidsafe_utilities;
extern crate config_file_handler;
extern crate crust;
extern crate docopt;
extern crate ip;

#[macro_use]
extern crate log;

extern crate rand;
extern crate rustc_serialize;
extern crate time;

use config_file_handler::FileHandler;
use crust::{Event, PeerId, Service};
use docopt::Docopt;
use ip::SocketAddrExt;
use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
use maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent;
use rand::{thread_rng, Rng};
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use time::{Duration, Tm};

type StdDuration = std::time::Duration;

static USAGE: &'static str = r#"
Usage:
    reporter <config>
    reporter (-h | --help)

Options:
    -h, --help                  Display this help message.

Example config file:

    {
        "start_listening": true,
        "start_service_discovery": true,
        "msg_to_send": "hello",
        "service_runs": 2,
        "output_report_path": "/tmp/file.json",
        "max_wait_before_restart_service_secs": 5,
        "max_msgs_per_sec": 25
    }

Explanation of the config fields:

    start_listening If true, this node will listen for incomming connections.

    start_service_discovery
                    If true, this node will start service discovery to find peers
                    on the local network.

    msg_to_send     Contents of the messages this node should send to other
                    nodes once is connected. Each node can specify a different
                    msg_to_send, so this information can be used to uniquely
                    identify a node on the network.

    service_runs    Number of times this node will fire a new Service. A new
                    Service is fired only once the previous one has stopped.

    max_wait_before_restart_service_secs
                    Maximum number of time (in seconds) the node should wait
                    before starting a new service (if there are remaining runs
                    to execute).

    max_msgs_per_sec
                    Maximum number of messages per second to send. Use this to
                    throttle the message sending. If blank or zero, there is
                    no throttling.

See also the example config files in examples/reporter directory.
"#;

const BEACON_PORT: u16 = 5484;
const MIN_RUN_TIME_MS: u64 = 1000;
const MAX_RUN_TIME_MS: u64 = 2500;
const WAIT_FOR_CONNECT_TIMEOUT: u64 = 10000;

fn main() {
    maidsafe_utilities::log::init(true);

    let args: Args = Docopt::new(USAGE)
                         .and_then(|d| d.decode())
                         .unwrap_or_else(|e| e.exit());

    let file_handler = unwrap_result!(FileHandler::new(&args.arg_config));
    let config = unwrap_result!(file_handler.read_file::<Config>());

    let mut report = Report::new();
    report.id = config.msg_to_send.clone();

    for i in 0..config.service_runs {
        debug!("Service started ({} of {})", i + 1, config.service_runs);
        report.update(run(&config));
        debug!("Service stopped ({} of {})", i + 1, config.service_runs);

        thread::sleep(StdDuration::from_millis(thread_rng().gen_range(
            0, config.max_wait_before_restart_service_secs * 1000)));
    }

    let file_handler = unwrap_result!(FileHandler::new(&config.output_report_path));
    unwrap_result!(file_handler.write_file(&report));
}

fn run(config: &Config) -> Report {
    let (category_tx, category_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();
    let (message_tx, message_rx) = mpsc::channel();
    let (connect_tx, connect_rx) = mpsc::channel();

    let event_sender = MaidSafeObserver::new(event_tx, CrustEvent, category_tx);
    let mut service = unwrap_result!(Service::new(event_sender, BEACON_PORT));

    if config.start_listening {
        unwrap_result!(service.start_listening_tcp());
        unwrap_result!(service.start_listening_utp());
    }

    if config.start_service_discovery {
        service.start_service_discovery();
    }

    let peers = Arc::new(Mutex::new(HashSet::new()));

    let event_join_handle = handle_service_events(category_rx, event_rx, message_tx.clone(), peers.clone());
    let message_join_handle = handle_messages(&config, service, message_rx, connect_tx, peers.clone());

    // Wait until we connect to someone
    let _ = recv_with_timeout(connect_rx,
                              StdDuration::from_millis(WAIT_FOR_CONNECT_TIMEOUT));

    // Keep it running for a (random) while.
    thread::sleep(StdDuration::from_millis(thread_rng()
                                               .gen_range(MIN_RUN_TIME_MS, MAX_RUN_TIME_MS)));

    // Kill everything and return the report.



    unwrap_result!(message_tx.send(None));
    unwrap_result!(message_join_handle.join());

    if let Ok(mut report) = event_join_handle.join() {
        report.record_break();
        report
    } else {
        Report::new()
    }
}

// Handle events from crust service.
fn handle_service_events(category_rx: Receiver<MaidSafeEventCategory>,
                         event_rx: Receiver<Event>,
                         message_tx: Sender<Option<PeerId>>,
                         peers: Arc<Mutex<HashSet<PeerId>>>)
                         -> JoinHandle<Report> {
    thread::spawn(move || {
        let mut report = Report::new();

        for category in category_rx.iter() {
            match category {
                CrustEvent => {
                    if let Ok(event) = event_rx.try_recv() {
                        report.record_event(&event);

                        match event {
                            Event::BootstrapAccept(peer_id) => {
                                debug!("BootstrapAccept {:?}", peer_id);
                                peers.lock().unwrap().insert(peer_id);
                                let _ = message_tx.send(Some(peer_id));
                            }

                            Event::BootstrapConnect(peer_id) => {
                                debug!("BootstrapConnect {:?}", peer_id);
                                peers.lock().unwrap().insert(peer_id);
                                let _ = message_tx.send(Some(peer_id));
                            }

                            Event::NewPeer(Ok(()), peer_id) => {
                                debug!("NewPeer {:?}", peer_id);
                                peers.lock().unwrap().insert(peer_id);
                                let _ = message_tx.send(Some(peer_id));
                            }

                            Event::LostPeer(peer_id) => {
                                debug!("LostPeer {:?}", peer_id);
                                peers.lock().unwrap().remove(&peer_id);
                            }

                            Event::NewMessage(peer_id, bytes) => {
                                debug!("NewMessage {:?}", peer_id);

                                if let Ok(string) = String::from_utf8(bytes) {
                                    report.record_message(&string);
                                    let _ = message_tx.send(Some(peer_id));
                                }
                            }
                            _ => (),
                        }
                    }
                }
                _ => unreachable!("This category should not have been fired - {:?}", category),
            }
        }

        report
    })
}

// Handle messages to be sent to other nodes.
fn handle_messages(config: &Config,
                   service: Service,
                   message_rx: Receiver<Option<PeerId>>,
                   connect_tx: Sender<()>,
                   peers: Arc<Mutex<HashSet<PeerId>>>)
                   -> JoinHandle<()> {
    let msgs_per_sec = config.max_msgs_per_sec.unwrap_or(0);
    let msg_time = if msgs_per_sec > 0 {
        Duration::milliseconds(1000 / msgs_per_sec as i64)
    } else {
        Duration::zero()
    };

    let message_bytes = config.msg_to_send.bytes().collect::<Vec<_>>();

    thread::spawn(move || {
        let mut sent_at = time::now() - msg_time;

        for peer_id in message_rx.iter() {
            match peer_id {
                Some(peer_id) => {
                    // Notify that we are now connected to someone, because we
                    // received a message.
                    let _ = connect_tx.send(());

                    // Sleep to throttle the number of messages sent.
                    let sleep = max(msg_time - (time::now() - sent_at), Duration::zero());
                    if sleep > Duration::zero() {
                        thread::sleep(StdDuration::from_millis(sleep.num_milliseconds() as u64));
                    }

                    if peers.lock().unwrap().contains(&peer_id) {
                        unwrap_result!(service.send(&peer_id, message_bytes.clone()));
                        sent_at = time::now();
                    }
                }
                None => break,
            }
        }

        for peer_id in peers.lock().unwrap().iter() {
            service.disconnect(peer_id);
        }
    })
}

#[derive(RustcDecodable)]
struct Args {
    arg_config: String,
}

#[derive(Debug, RustcDecodable)]
struct Config {
    msg_to_send: String,
    start_listening: bool,
    start_service_discovery: bool,
    service_runs: u64,
    output_report_path: String,
    max_wait_before_restart_service_secs: u64,
    max_msgs_per_sec: Option<u32>,
}

#[derive(Debug, RustcEncodable)]
struct Report {
    id: String,
    msgs_recvd: HashMap<String, u64>,
    events: Vec<Option<EventEntry>>,
}

impl Report {
    fn new() -> Self {
        Report {
            id: String::new(),
            msgs_recvd: HashMap::new(),
            events: Vec::new(),
        }
    }

    fn record_message(&mut self, message: &str) {
        let counter = self.msgs_recvd.entry(message.to_string()).or_insert(0);
        *counter += 1;
    }

    fn record_event(&mut self, event: &Event) {
        self.events.push(Some(EventEntry {
            timestamp: time::now(),
            description: Self::format_event(event),
        }));
    }

    fn record_break(&mut self) {
        self.events.push(None);
    }

    fn update(&mut self, other: Report) {
        for (key, value) in other.msgs_recvd.iter() {
            let counter = self.msgs_recvd.entry(key.clone()).or_insert(0);
            *counter += *value;
        }

        self.events.extend(other.events);
    }

    fn format_event(event: &Event) -> String {
        match *event {
            Event::NewMessage(ref connection, ref data) => {
                format!("NewMessage({:?}, \"{}\")",
                        connection,
                        String::from_utf8_lossy(&data))
            }
            _ => format!("{:?}", event),
        }
    }
}

#[derive(Debug)]
struct EventEntry {
    timestamp: Tm,
    description: String,
}

impl Encodable for EventEntry {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        let timestamp_string = format!("{}", self.timestamp.rfc3339());
        [&timestamp_string, &self.description].encode(encoder)
    }
}

enum RecvWithTimeoutError {
    Disconnected,
    Timeout,
}

fn recv_with_timeout<T>(receiver: Receiver<T>,
                        timeout: StdDuration)
                        -> Result<T, RecvWithTimeoutError> {
    let interval = StdDuration::from_millis(100);
    let mut elapsed = StdDuration::from_millis(0);

    loop {
        match receiver.try_recv() {
            Ok(value) => return Ok(value),
            Err(mpsc::TryRecvError::Disconnected) => return Err(RecvWithTimeoutError::Disconnected),
            _ => (),
        }

        thread::sleep(interval);
        elapsed = elapsed + interval;

        if elapsed > timeout {
            break;
        }
    }

    Err(RecvWithTimeoutError::Timeout)
}

