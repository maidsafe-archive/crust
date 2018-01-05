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

//! This example demonstrates how to make a P2P connection using `crust`.
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
extern crate docopt;
extern crate void;
extern crate future_utils;
extern crate env_logger;

extern crate crust;


use crust::{ConfigFile, PaAddr, Peer, PubConnectionInfo, Service, Uid};
use crust::config::DevConfigSettings;
use docopt::Docopt;
use future_utils::{BoxFuture, FutureExt, thread_future};
use futures::{Future, Sink, Stream, future};
use futures::future::{Either, Loop};
use std::{fmt, io};
use tokio_core::reactor::Core;
use void::Void;

const USAGE: &str = "
Usage:
    chat [--rendezvous-peer=<addr>] [--disable-tcp] [--disable-igd]
    chat (-h | --help)

Options:
    -h --help                   Show this screen.
    --rendezvous-peer=<addr>    Address of peer to use as a rendezvous server.
    --disable-tcp               Connect using uTP only.
    --disable-igd               Disable IGD/UPnP.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_rendezvous_peer: Option<PaAddr>,
    flag_disable_tcp: bool,
    flag_disable_igd: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Rand)]
struct PeerId(u64);

impl Uid for PeerId {}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let PeerId(ref id) = *self;
        write!(f, "{:x}", id)
    }
}

fn main() {
    unwrap!(env_logger::init());

    let args: Args = {
        Docopt::new(USAGE)
            .and_then(|d| d.deserialize())
            .unwrap_or_else(|e| e.exit())
    };

    let config = unwrap!(ConfigFile::new_temporary());
    if let Some(rendezvous_addr) = args.flag_rendezvous_peer {
        unwrap!(config.write()).hard_coded_contacts = vec![rendezvous_addr];
    }
    if args.flag_disable_tcp {
        unwrap!(config.write()).dev = Some(DevConfigSettings {
            disable_tcp: true,
            ..Default::default()
        });
    }

    let mut core = unwrap!(Core::new());
    let handle = core.handle();

    let our_uid = rand::random();

    let future = {
        Service::with_config(&handle, config, our_uid)
            .map_err(|e| panic!("error starting service: {}", e))
            .and_then(|service| {
                if args.flag_disable_igd {
                    service.p2p_config().disable_igd();
                }

                service
                    .prepare_connection_info()
                    .map_err(|e| panic!("error preparing connection info: {}", e))
                    .and_then(move |our_priv_info| {
                        let our_pub_info = our_priv_info.to_pub_connection_info();
                        let as_str = unwrap!(serde_json::to_string(&our_pub_info));
                        println!("Our connection info:");
                        println!("{}", as_str);
                        println!("");
                        println!(
                            "Copy this info and share it with your connecting partner. Then paste \
                          their info below."
                        );
                        read_line().and_then(move |line| {
                            let their_pub_info: PubConnectionInfo<PeerId> = unwrap!(
                        serde_json::from_str(&line)
                    );

                            service
                                .connect(our_priv_info, their_pub_info)
                                .map_err(|e| panic!("error connecting to peer: {}", e))
                                .and_then(move |peer| have_a_conversation(service, peer))
                        })
                    })
            })
    };

    match core.run(future) {
        Ok(()) => (),
        Err(v) => void::unreachable(v),
    }
}

fn read_line() -> BoxFuture<String, Void> {
    thread_future(|| {
        let stdin = io::stdin();
        let mut line = String::new();
        unwrap!(stdin.read_line(&mut line));
        line
    }).into_boxed()
}

fn have_a_conversation(service: Service<PeerId>, peer: Peer<PeerId>) -> BoxFuture<(), Void> {
    let (peer_sink, peer_stream) = peer.split();

    println!("You are now connected! say hello :)");
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
