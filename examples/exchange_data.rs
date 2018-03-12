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

//! This example demonstrates how to exchange data between two P2P nodes.
//!
//! In a nutshell all it does is:
//!
//! 1. connects to remote peer (for connection details see `connect.rs` sample)
//! 2. sends "Hello from peer '`$peer_id`'" message
//! 3. sends "Goodbye from peer '`$peer_id`'" message
//! 4. prints any messages received from remote peer
//!
//! To modify example behavior edit *sample.config* file. It's a Crust config that `exchange_data`
//! expects to be located next to executable.

#[macro_use]
extern crate unwrap;
extern crate tokio_core;
extern crate futures;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate rand;
#[macro_use]
extern crate rand_derive;
extern crate void;
extern crate future_utils;
extern crate env_logger;

extern crate crust;

mod utils;

use crust::{ConfigFile, PubConnectionInfo, Service};
use future_utils::{BoxFuture, FutureExt, thread_future};
use futures::future::{Future, empty};
use futures::sink::Sink;
use futures::stream::Stream;
use std::io;
use tokio_core::reactor::Core;
use utils::PeerId;
use void::Void;

fn main() {
    unwrap!(env_logger::init());

    let mut event_loop = unwrap!(Core::new());
    let handle = event_loop.handle();
    // generate random unique ID for this node
    let service_id: PeerId = rand::random();
    println!("Service id: {}", service_id);

    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![
        unwrap!("tcp://0.0.0.0:0".parse()),
        unwrap!("utp://0.0.0.0:0".parse()),
    ];
    let service = unwrap!(event_loop.run(
        Service::with_config(&handle, config, service_id),
    ));
    let listeners = unwrap!(event_loop.run(service.start_listening().collect()));
    for listener in &listeners {
        println!("Listening on {}", listener.addr());
    }

    let our_conn_info = unwrap!(event_loop.run(service.prepare_connection_info()));
    let pub_conn_info = our_conn_info.to_pub_connection_info();
    println!(
        "Public connection information:\n{}\n",
        unwrap!(serde_json::to_string(&pub_conn_info))
    );

    println!("Enter remote peer public connection info:");
    // does the p2p connection
    let connect = read_line().infallible().and_then(move |ln| {
        let their_info: PubConnectionInfo<PeerId> = unwrap!(serde_json::from_str(&ln));
        service.connect(our_conn_info, their_info).map(
            move |peer| {
                (peer, service)
            },
        )
    });
    let (peer, _service) = unwrap!(event_loop.run(connect));
    println!(
        "Connected to peer: {}, {}",
        peer.uid(),
        unwrap!(peer.addr())
    );

    let (peer_sink, peer_stream) = peer.split();
    // spawn an asynchronous task that handles incoming data
    handle.spawn(
        peer_stream
            .for_each(|data: Vec<u8>| {
                println!("Received: {}", unwrap!(String::from_utf8(data)));
                Ok(()) // keep receiving data
            })
            // adapt to Handle::spawn() requirements, see:
            // https://docs.rs/tokio-core/0.1.10/tokio_core/reactor/struct.Handle.html#method.spawn
            .then(|_| Ok(())),
    );

    // lower priority is higher, 0 is the highest.
    // Note that 0 is used for internal crust messages though.
    let msg_priority = 1;
    let hello_msg = format!("Hello from peer '{}'!", service_id).into_bytes();
    let bye_msg = format!("Goodbye from peer '{}'!", service_id).into_bytes();

    // let's send multiple messages to connected peer
    unwrap!(event_loop.run(
        peer_sink
        .send((msg_priority, hello_msg)) // send first message
        .and_then(|peer_sink| { // when it's done, send the second
            // sink.send() on completion returns sink which implements Future trait
            peer_sink.send((msg_priority, bye_msg))
        }),
    ));

    // Run event loop forever.
    let res = event_loop.run(empty::<(), ()>());
    unwrap!(res);
}

/// Reads single line from stdin.
fn read_line() -> BoxFuture<String, Void> {
    thread_future(|| {
        let stdin = io::stdin();
        let mut line = String::new();
        unwrap!(stdin.read_line(&mut line));
        line
    }).into_boxed()
}
