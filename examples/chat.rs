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
#[macro_use]
extern crate clap;

extern crate crust;

mod utils;

use clap::{App, Arg};
use crust::{ConfigFile, PaAddr, Peer, PubConnectionInfo, Service};
use crust::config::{DevConfigSettings, PeerInfo};
use future_utils::{BoxFuture, FutureExt};
use futures::{Future, Sink, Stream, future};
use futures::future::{Either, Loop};
use rust_sodium::crypto::box_::PublicKey;
use std::str::FromStr;
use tokio_core::reactor::{Core, Handle};
use utils::{PeerId, read_line};
use void::Void;

#[derive(Debug)]
struct Args {
    flag_rendezvous_peer: Option<PaAddr>,
    flag_rendezvous_peer_key: Option<String>,
    flag_disable_tcp: bool,
    flag_disable_igd: bool,
}

fn main() {
    unwrap!(env_logger::init());
    let args = parse_cli_args();
    let mut core = unwrap!(Core::new());
    let handle = core.handle();

    let future = Node::run(&handle, args)
        .and_then(|node| node.connect())
        .and_then(|(node, peer)| have_a_conversation(node.service, peer));
    match core.run(future) {
        Ok(()) => (),
        Err(v) => void::unreachable(v),
    }
}

/// Chat node/peer
struct Node {
    service: Service<PeerId>,
}

impl Node {
    /// Constructs Crust `Service` and starts listeners.
    fn run(handle: &Handle, args: Args) -> BoxFuture<Self, Void> {
        let config = args.make_config();
        let our_uid = rand::random();
        Service::with_config(handle, config, our_uid)
            .map_err(|e| panic!("error starting service: {}", e))
            .map(move |service| {
                if args.flag_disable_igd {
                    service.p2p_config().disable_igd();
                }
                Self { service }
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
                println!("Our connection info:");
                println!("{}", as_str);
                println!();
                println!(
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
}

fn parse_cli_args() -> Args {
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
        .get_matches();

    let rendezvous_peer = matches.value_of("rendezvous-peer")
        .map(|addr| unwrap!(PaAddr::from_str(addr)));
    let rendezvous_peer_key = matches.value_of("rendezvous-peer-key").map(|addr| addr.to_owned());
    Args {
        flag_rendezvous_peer: rendezvous_peer,
        flag_rendezvous_peer_key: rendezvous_peer_key,
        flag_disable_tcp: matches.occurrences_of("disable-tcp") > 0,
        flag_disable_igd: matches.occurrences_of("disable-igd") > 0,
    }
}

impl Args {
    /// Constructs `Crust` config from CLI arguments.
    fn make_config(&self) -> ConfigFile {
        let config = unwrap!(ConfigFile::new_temporary());
        if let Some(rendezvous_addr) = self.flag_rendezvous_peer {
            let peer_pub_key =
                unwrap!(
                self.flag_rendezvous_peer_key.clone(),
                "If rendezvous peer is specified, it's public key must be given too.",
            );
            let peer_pub_key: PublicKey = unwrap!(serde_json::from_str(&peer_pub_key));
            let peer_info = PeerInfo::new(rendezvous_addr, peer_pub_key);
            unwrap!(config.write()).hard_coded_contacts = vec![peer_info];
        }

        if self.flag_disable_tcp {
            unwrap!(config.write()).dev = Some(DevConfigSettings {
                disable_tcp: true,
                ..Default::default()
            });
        }

        config
    }
}

fn have_a_conversation(service: Service<PeerId>, peer: Peer<PeerId>) -> BoxFuture<(), Void> {
    println!(
        "You are now connected to '{}'! say hello :)",
        unwrap!(peer.addr())
    );

    let (peer_sink, peer_stream) = peer.split();
    let writer = {
        future::loop_fn(peer_sink, |peer_sink| {
            read_line().and_then(|line| {
                let line = line.into_bytes();
                peer_sink.send((0, line)).map(Loop::Continue).map_err(|e| {
                    panic!("error sending message to peer: {}", e)
                })
            })
        })
    };
    let reader = {
        peer_stream
        .map_err(|e| panic!("error receiving message from peer: {}", e))
        .for_each(|line| {
            let line = match String::from_utf8(line) {
                Ok(line) => line,
                Err(..) => String::from("<peer sent invalid utf8>"),
            };
            println!("{}", line);
            Ok(())
        })
        .map(|()| {
            println!("peer disconnected");
        })
    };

    writer
        .select2(reader)
        .map(|either| match either {
            Either::A((v, _next)) => void::unreachable(v),
            Either::B(((), _next)) => drop(service),
        })
        .map_err(|either| match either {
            Either::A((v, _next)) => v,
            Either::B((v, _next)) => v,
        })
        .into_boxed()
}
