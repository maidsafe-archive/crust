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
use std::sync::mpsc::channel;
use std::thread;
use time::Tm;

static USAGE: &'static str = "
Usage:
    reporter <config>
";

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

    for i in 0..config.service_runs {
        debug!("Service started ({} of {})", i + 1, config.service_runs);
        report.update(run(&config));
        debug!("Service stopped ({} of {})", i + 1, config.service_runs);

        thread::sleep_ms(thread_rng().gen_range(0, config.max_wait_before_restart_service_secs * 1000));
    }

    let mut file_handler = FileHandler::new(Path::new(&config.output_report_path).to_path_buf());
    file_handler.write_file(&report).unwrap();
}

#[derive(RustcDecodable)]
struct Args {
    arg_config: String
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
            for sa in self.ips.iter_mut() {
                sa.ensure_port(port);
            }
        }
    }
}

// This is a wrapper for std::net::SocketAdds so we can implement Decodable
// for it.
#[derive(Debug)]
struct SocketAddr(std::net::SocketAddr);

impl SocketAddr {
    // Set the port of the address to the given port if it is zero, otherwise
    // leave it unchanged.
    fn ensure_port(&mut self, port: u16) {
        use std::net::SocketAddr::{V4, V6};
        use std::net::{SocketAddrV4, SocketAddrV6};

        if self.0.port() != 0 { return; }

        self.0 = match self.0 {
            V4(a) => V4(SocketAddrV4::new(*a.ip(), port)),
            V6(a) => V6(SocketAddrV6::new(*a.ip(), port, a.flowinfo(), a.scope_id()))
        }
    }
}

impl Decodable for SocketAddr {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
        let encoded = try!(d.read_str());

        // Try to parse first as address:port pair, if that fails, parse it as
        // IPv4 address only. If even that fails, parse it as IPv6 address only.
        encoded.parse::<std::net::SocketAddr>().or_else(|_| {
            encoded.parse::<std::net::Ipv4Addr>().map(|a| {
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(a, 0))
            })
        }).or_else(|_| {
            encoded.parse::<std::net::Ipv6Addr>().map(|a| {
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(a, 0, 0, 0))
            })
        }).map(|s| SocketAddr(s)).map_err(|_| d.error("Invalid socket address"))
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
            description: format!("{:?}", event)
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
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let timestamp_string = format!("{}", self.timestamp.rfc3339());
        [&timestamp_string, &self.description].encode(e)
    }
}

fn run(config: &Config) -> Report {
    let (event_sender, event_receiver) = channel();
    let (message_sender0, message_receiver) = channel();
    let message_sender1 = message_sender0.clone();

    let mut service = Service::new(event_sender).unwrap();

    if !config.ips.is_empty() {
        connect_to_all(&mut service, &config.ips);
    }

    if let Some(port) = config.listening_port {
        start_accepting(&mut service, port).unwrap();
    }

    let message_bytes = config.msg_to_send.bytes().collect::<Vec<_>>();

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
    let message_thread_handle = thread::spawn(move || {
        for connection in message_receiver.iter() {
            match connection {
                Some(connection) => {
                    service.send(connection, message_bytes.clone());
                },
                None => {
                    service.stop();
                    break;
                }
            };
        }
    });

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
        service.connect(vec![Endpoint::Tcp(addr)]);
        service.connect(vec![Endpoint::Utp(addr)]);
    }
}

fn start_accepting(service: &mut Service, port: u16) -> io::Result<()> {
    if let Err(e) = service.start_accepting(Port::Tcp(port)) { return Err(e); }

    // FIXME: this panics on the second run, with "Address already in use"
    //        error. Seems like Service is not cleaning up it's stuff properly
    //        when stopped.
    // if let Err(e) = service.start_accepting(Port::Utp(port)) { return Err(e); }

    Ok(())
}
