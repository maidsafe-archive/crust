// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! This example demonstrates how to make a rendezvous connection using `crust`.
//!
//! In order to make a connection we need to:
//!
//! 1. create a `Service` object.
//! 2. call `prepare_connection_info` to obtain a `PrivConnectionInfo`
//! 3. create a `PubConnectionInfo` from our `PrivConnectionInfo`
//! 4. exchange `PubConnectionInfo` objects with the peer we are connecting to.
//! 5. call `connect` using the peer's `PubConnectionInfo` and our `PrivConnectionInfo`
//!
//! Run two instances of this sample: preferably on separate computers but
//! localhost is fine too.
//! When the sample starts it prints generated public information which
//! is represented as JSON object.
//! Copy this object from first to second peer and hit ENTER.
//! Do the same with the second peer: copy it's public information JSON
//! to first peer and hit ENTER.
//! On both peers you should see something like:
//! ```
//! You are now connected! say hello :)
//! ```
//! That's it, it means we successfully did a peer-to-peer connection. You can now use this
//! connection to chat to the remote peer.

#[macro_use]
extern crate unwrap;
extern crate tokio_core;
extern crate futures;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate rand_derive;
extern crate rand;
extern crate void;
extern crate future_utils;
extern crate env_logger;
extern crate rust_sodium;
extern crate clap;
extern crate chrono;

extern crate crust;

mod utils;

use chrono::Local;
use clap::{App, Arg};
use crust::{ConfigFile, Listener, PaAddr, Peer, PubConnectionInfo, Service};
use crust::config::{DevConfigSettings, PeerInfo};
use future_utils::{BoxFuture, FutureExt};
use futures::{Future, Sink, Stream, future};
use futures::future::{Either, Loop};
use std::io::{self, Write};
use std::process;
use std::str::FromStr;
use tokio_core::reactor::{Core, Handle};
use utils::{PeerId, read_line};
use void::Void;

/// Prints current time and given formatted string.
macro_rules! out {
    ($($arg:tt)*) => {
        let date = Local::now();
        print!("\r{} ", date.format("%H:%M"));
        println!($($arg)*);
    };
}

#[derive(Debug)]
struct Args {
    rendezvous_peer: Option<PeerInfo>,
    disable_tcp: bool,
    disable_igd: bool,
    disable_direct_connections: bool,
}

fn main() {
    unwrap!(env_logger::init());
    let args = match parse_cli_args() {
        Ok(args) => args,
        Err(e) => e.exit(),
    };
    let mut core = unwrap!(Core::new());
    let handle = core.handle();

    print_logo();

    let future = Node::run(&handle, args)
        .and_then(|node| node.connect())
        .and_then(|(node, peer)| node.have_a_conversation_with(peer));
    match core.run(future) {
        Ok(()) => (),
        Err(v) => void::unreachable(v),
    }
}

/// Chat node/peer
struct Node {
    service: Service<PeerId>,
    #[allow(unused)]
    listeners: Vec<Listener>,
}

impl Node {
    /// Constructs Crust `Service` and starts listeners.
    fn run(handle: &Handle, args: Args) -> BoxFuture<Self, Void> {
        let config = args.make_config();
        let our_uid = rand::random();
        Service::with_config(handle, config, our_uid)
            .map_err(|e| panic!("error starting service: {}", e))
            .map(move |service| {
                if args.disable_igd {
                    service.p2p_config().disable_igd();
                }
                service
            })
            .and_then(|service| {
                out!("Our ID: {}", service.id());
                service
                    .start_listening()
                    .map_err(|e| panic!("Failed to start listeners: {}", e))
                    .collect()
                    .map(move |listeners| Self { service, listeners })
            })
            .into_boxed()
    }

    /// Get peer info from stdin and attempt to connect to it.
    fn connect(self) -> BoxFuture<(Node, Peer<PeerId>), Void> {
        self.service
            .prepare_connection_info()
            .map_err(|e| panic!("error preparing connection info: {}", e))
            .and_then(move |our_priv_info| {
                let our_pub_info = our_priv_info.to_pub_connection_info();
                let as_str = unwrap!(serde_json::to_string(&our_pub_info));
                out!("Our connection info:");
                println!("{}", as_str);
                println!();
                out!(
                    "Copy this info and share it with your connecting partner. Then paste \
                  their info below."
                );
                read_line().and_then(move |ln| {
                    let their_pub_info: PubConnectionInfo<_> = unwrap!(serde_json::from_str(&ln));
                    self.service
                        .connect(our_priv_info, their_pub_info)
                        .map_err(|e| panic!("error connecting to peer: {}", e))
                        .map(move |peer| (self, peer))
                })
            })
            .into_boxed()
    }

    fn have_a_conversation_with(self, peer: Peer<PeerId>) -> BoxFuture<(), Void> {
        out!(
            "You are now connected to '{}'! Say hello :) Or type /help to see possible commands.",
            unwrap!(peer.addr())
        );

        let peer_display_name = peer.uid();
        let (peer_sink, peer_stream) = peer.split();
        let writer = {
            future::loop_fn(peer_sink, |peer_sink| {
                print!("> ");
                unwrap!(io::stdout().flush());
                read_line().and_then(|line| {
                    let line = line.trim_right().to_owned();
                    if !handle_cmd(&line) {
                        peer_sink
                            .send((0, line.into_bytes()))
                            .map(Loop::Continue)
                            .map_err(|e| panic!("error sending message to peer: {}", e))
                            .into_boxed()
                    } else {
                        future::ok(Loop::Continue(peer_sink)).into_boxed()
                    }
                })
            })
        };
        let reader = {
            peer_stream
            .map_err(|e| panic!("error receiving message from peer: {}", e))
            .for_each(move |line| {
                let line = match String::from_utf8(line) {
                    Ok(line) => line,
                    Err(..) => String::from("<peer sent invalid utf8>"),
                };
                out!("<{}> {}", peer_display_name, line);
                print!("> ");
                unwrap!(io::stdout().flush());
                Ok(())
            })
            .map(move |()| {
                out!("Peer <{}> disconnected", peer_display_name);
            })
        };

        writer
            .select2(reader)
            .map(move |either| match either {
                Either::A((v, _next)) => void::unreachable(v),
                Either::B(((), _next)) => drop(self.service),
            })
            .map_err(|either| match either {
                Either::A((v, _next)) => v,
                Either::B((v, _next)) => v,
            })
            .into_boxed()
    }
}

fn parse_cli_args() -> Result<Args, clap::Error> {
    let matches = App::new("Simple chat app built on Crust")
        .about(
            "This chat app connects two machines directly without intermediate servers and allows \
to exchange messages securely. All the messages are end to end encrypted.",
        )
        .arg(
            Arg::with_name("rendezvous-peer")
                .long("rendezvous-peer")
                .value_name("ADDR")
                .help("Address of peer to use as a rendezvous server.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("rendezvous-peer-key")
                .long("rendezvous-peer-key")
                .value_name("KEY")
                .help("Rendezvous peer public key.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("disable-tcp")
                .long("disable-tcp")
                .help("Connect using uTP only.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("disable-igd")
                .long("disable-igd")
                .help("Disable IGD/UPnP.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("disable-direct-connections")
                .long("disable-direct-connections")
                .help(
                    "By default chat will try to connect to the peer in all possible methods: \
                      directly or via hole punching. This flag disables direct connections leaving \
                      only rendezvous connections to try.",
                )
                .takes_value(false),
        )
        .get_matches();

    let rendezvous_peer = match matches.value_of("rendezvous-peer") {
        Some(addr) => {
            let peer_addr = unwrap!(PaAddr::from_str(addr));
            let peer_key = matches
                .value_of("rendezvous-peer-key")
                .map(|key| unwrap!(serde_json::from_str(key)))
                .ok_or_else(|| {
                    clap::Error::with_description(
                        "If rendezvous peer address is given, public key must be present too.",
                        clap::ErrorKind::EmptyValue,
                    )
                })?;
            Some(PeerInfo::new(peer_addr, peer_key))
        }
        None => None,
    };
    Ok(Args {
        rendezvous_peer,
        disable_tcp: matches.occurrences_of("disable-tcp") > 0,
        disable_igd: matches.occurrences_of("disable-igd") > 0,
        disable_direct_connections: matches.occurrences_of("disable-direct-connections") > 0,
    })
}

impl Args {
    /// Constructs `Crust` config from CLI arguments.
    fn make_config(&self) -> ConfigFile {
        let config = unwrap!(ConfigFile::new_temporary());

        if let Some(ref peer_info) = self.rendezvous_peer {
            unwrap!(config.write()).hard_coded_contacts = vec![peer_info.clone()];
        }
        if self.disable_tcp {
            unwrap!(config.write()).dev = Some(DevConfigSettings {
                disable_tcp: true,
                ..Default::default()
            });
        }
        if !self.disable_direct_connections {
            unwrap!(config.write()).listen_addresses = vec![
                unwrap!("utp://0.0.0.0:0".parse()),
                unwrap!("tcp://0.0.0.0:0".parse()),
            ];
        }

        config
    }
}

fn handle_cmd(cmd: &String) -> bool {
    let mut valid_command = false;
    if cmd.starts_with("/send") {
        println!("Let's send a file: {}", cmd[6..].to_owned());
        valid_command = true;
    } else if cmd.starts_with("/exit") {
        process::exit(0);
    } else if cmd.starts_with("/help") {
        println!("Possible commands:");
        println!("  /help - prints this help menu");
        println!("  /exit - terminates chat app");
        println!(
            "  /send $file_path - attempts to send given file to connected peer. File path \
                 might be relative or absolute."
        );
        valid_command = true;
    }
    valid_command
}

fn print_logo() {
    println!(
        r#"
   _____                _      _____ _           _
  / ____|              | |    / ____| |         | |
 | |     _ __ _   _ ___| |_  | |    | |__   __ _| |_
 | |    | '__| | | / __| __| | |    | '_ \ / _` | __|
 | |____| |  | |_| \__ \ |_  | |____| | | | (_| | |_
  \_____|_|   \__,_|___/\__|  \_____|_| |_|\__,_|\__|

  "#
    );
}
