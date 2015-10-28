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

#![forbid(missing_docs, warnings)]
#![deny(bad_style, deprecated, drop_with_repr_extern, improper_ctypes, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints,
        unsafe_code, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

extern crate crust;
extern crate docopt;
extern crate env_logger;

#[macro_use]
extern crate log;

extern crate rand;
extern crate rustc_serialize;
extern crate time;

use crust::{Endpoint, Event, FileHandler,  Port, Service};
use docopt::Docopt;
use rand::{thread_rng, Rng};
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use time::Tm;

static USAGE: &'static str = r#"
Usage:
    reporter [-i | --connect-immediately] <config>
    reporter (-h | --help)

Options:
    -i, --connect-immediately   If this flag is set, this node will connect to
                                other nodes and start sending messages
                                immediately. Otherwise, it will wait until
                                someone connects to it first.
    -h, --help                  Display this help message.

Example config file:

    {
        "ips": ["123.124.125.126", "223.224.225.226:1234"],
        "listening_port": 9999,
        "msg_to_send": "hello",
        "service_runs": 2,
        "output_report_path": "/tmp/file.json",
        "max_wait_before_restart_service_secs": 5
    }

Explanation of the config fields:

    ips             IPs (and optionally ports) this node should try to
                    connect to. Those without port specified are assumed to
                    listen on listening_port.

    listening_port  Port this node listens on.

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

See also the example config files in examples/reporter directory.
"#;

const MIN_RUN_TIME_MS: u32 = 1000;
const MAX_RUN_TIME_MS: u32 = 2500;

fn main() {
    match env_logger::init() {
        Ok(()) => {},
        Err(e) => println!("Error initialising logger; continuing without: {:?}", e)
    }

    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode())
                                       .unwrap_or_else(|e| e.exit());

    let mut file_handler = FileHandler::new(Path::new(&args.arg_config).to_path_buf());

    let mut config = file_handler.read_file::<Config>().unwrap();
    config.sanitize();

    let mut report = Report::new();
    report.id = config.msg_to_send.clone();

    let connected = Arc::new(AtomicBool::new(args.flag_connect_immediately));

    for i in 0..config.service_runs {
        debug!("Service started ({} of {})", i + 1, config.service_runs);
        report.update(run(connected.clone(), &config));
        debug!("Service stopped ({} of {})", i + 1, config.service_runs);

        thread::sleep_ms(thread_rng().gen_range(
            0, config.max_wait_before_restart_service_secs * 1000));
    }

    let mut file_handler = FileHandler::new(Path::new(&config.output_report_path).to_path_buf());
    file_handler.write_file(&report).unwrap();
}

#[derive(RustcDecodable)]
struct Args {
    arg_config: String,
    flag_connect_immediately: bool
}

#[derive(Debug, RustcDecodable)]
struct Config {
    ips:                                  Vec<SocketAddr>,
    msg_to_send:                          String,
    listening_port:                       Option<u16>,
    service_runs:                         u64,
    output_report_path:                   String,
    max_wait_before_restart_service_secs: u32
}

impl Config {
    // If the ips have no explicit ports, assign them the same port as in
    // the listening_port field.
    fn sanitize(&mut self) {
        if let Some(port) = self.listening_port {
            for addr in self.ips.iter_mut() {
                addr.ensure_port(port);
            }
        }
    }
}

// This is a wrapper for std::net::SocketAdds so we can implement Decodable
// for it.
#[derive(Clone, Debug)]
struct SocketAddr(std::net::SocketAddr);

impl SocketAddr {
    // Set the port of the address to the given port if it is zero, otherwise
    // leave it unchanged.
    fn ensure_port(&mut self, port: u16) {
        use std::net::SocketAddr::{V4, V6};
        use std::net::{SocketAddrV4, SocketAddrV6};

        if self.0.port() != 0 { return; }

        self.0 = match self.0 {
            V4(addr) => V4(SocketAddrV4::new(*addr.ip(), port)),
            V6(addr) => V6(SocketAddrV6::new(*addr.ip(), port, addr.flowinfo(), addr.scope_id()))
        }
    }
}

impl Decodable for SocketAddr {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, D::Error> {
        let encoded = try!(decoder.read_str());

        // Try to parse first as address:port pair, if that fails, parse it as
        // IPv4 address only. If even that fails, parse it as IPv6 address only.
        encoded.parse::<std::net::SocketAddr>().or_else(|_| {
            encoded.parse::<std::net::Ipv4Addr>().map(|ip| {
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, 0))
            })
        }).or_else(|_| {
            encoded.parse::<std::net::Ipv6Addr>().map(|ip| {
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, 0, 0, 0))
            })
        }).map(|addr| SocketAddr(addr)).map_err(|_| {
            decoder.error("Invalid socket address")
        })
    }
}

#[derive(Debug, RustcEncodable)]
struct Report {
    id: String,
    msgs_recvd: HashMap<String, u64>,
    events: Vec<Option<EventEntry>>
}

impl Report {
    fn new() -> Report {
        Report {
            id: String::new(),
            msgs_recvd: HashMap::new(),
            events: Vec::new()
        }
    }

    fn record_message(&mut self, message: &str) {
        let counter = self.msgs_recvd.entry(message.to_string()).or_insert(0);
        *counter += 1;
    }

    fn record_event(&mut self, event: &Event) {
        self.events.push(Some(EventEntry {
            timestamp:   time::now(),
            description: format_event(event)
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
}

#[derive(Debug)]
struct EventEntry {
    timestamp: Tm,
    description: String
}

impl Encodable for EventEntry {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        let timestamp_string = format!("{}", self.timestamp.rfc3339());
        [&timestamp_string, &self.description].encode(encoder)
    }
}

fn format_event(event: &Event) -> String {
    match *event {
        Event::NewMessage(ref connection, ref data) => {
            format!("NewMessage({:?}, \"{}\")", connection,
                    String::from_utf8_lossy(&data))
        },
        _ => format!("{:?}", event)
    }
}

fn run(connected: Arc<AtomicBool>, config: &Config) -> Report {
    let (event_sender, event_receiver) = channel();

    let (message_sender0, message_receiver) = channel();
    let message_sender1 = message_sender0.clone();

    // This channel is used to wait until someone connects to us.
    let (wait_sender, wait_receiver) = channel();

    let mut service = Service::new(event_sender).unwrap();

    if connected.load(Ordering::Relaxed) {
        if !config.ips.is_empty() {
            connect_to_all(&mut service, &config.ips);
        }

        wait_sender.send(()).unwrap();
    }

    if let Some(port) = config.listening_port {
        start_accepting(&mut service, port).unwrap();
    }

    let message_bytes = config.msg_to_send.bytes().collect::<Vec<_>>();
    let ips = config.ips.clone();

    // This thread is for receiving events from the service.
    let event_thread_handle = thread::spawn(move || {
        let mut report = Report::new();

        for event in event_receiver.iter() {
            report.record_event(&event);

            match event {
                Event::OnAccept(connection) => {
                    debug!("OnAccept {:?}", connection);
                    let _ = message_sender0.send(Some(connection));
                },

                Event::OnConnect(connection) => {
                    debug!("OnConnect {:?}", connection);
                    let _ = message_sender0.send(Some(connection));
                },

                Event::NewMessage(connection, bytes) => {
                    debug!("NewMessage {:?}", connection);

                    if let Ok(string) = String::from_utf8(bytes) {
                        report.record_message(&string);
                        let _ = message_sender0.send(Some(connection));
                    }
                },

                _ => ()
            }
        }

        return report;
    });

    // This thread is for sending messages via the service.
    let connected2 = connected.clone();
    let message_thread_handle = thread::spawn(move || {
        for connection in message_receiver.iter() {
            match connection {
                Some(connection) => {
                    service.send(connection, message_bytes.clone());

                    if !connected2.swap(true, Ordering::Relaxed) {
                        connect_to_all(&mut service, &ips);
                        wait_sender.send(()).unwrap();
                    }
                },
                None => {
                    service.stop();
                    break;
                }
            };
        }
    });

    // Wait until someone connects to us.
    let _ = wait_receiver.recv();

    thread::sleep_ms(thread_rng().gen_range(MIN_RUN_TIME_MS, MAX_RUN_TIME_MS));

    message_sender1.send(None).unwrap();
    message_thread_handle.join().unwrap();

    if let Ok(mut report) = event_thread_handle.join() {
        report.record_break();
        report
    } else {
        Report::new()
    }
}

fn connect_to_all(service: &mut Service, addrs: &[SocketAddr]) {
    for addr in addrs {
        let addr = addr.0;

        debug!("Connecting to {}", addr);

        service.connect(vec![Endpoint::Tcp(addr)]);
        service.connect(vec![Endpoint::Utp(addr)]);
    }
}

fn start_accepting(service: &mut Service, port: u16) -> io::Result<()> {
    if let Err(e) = service.start_accepting(Port::Tcp(port)) { return Err(e); }

    // FIXME: this panics on the second run, with "Address already in use"
    //        error. Seems like Service is not cleaning up it's stuff properly
    //        when stopped.
    //        When issue #361 is resolved, this can be uncommented.
    // if let Err(e) = service.start_accepting(Port::Utp(port)) { return Err(e); }

    Ok(())
}
