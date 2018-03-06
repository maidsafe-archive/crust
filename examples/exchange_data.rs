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
//! To modify example behavior edit *sample.config* file. It's a Crust config that exchange_data
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

extern crate crust;

use futures::future::{Future, empty};
use futures::sink::Sink;
use futures::stream::Stream;
use tokio_core::reactor::Core;

mod utils;
use utils::{PeerId, connect_to_peer};

fn main() {
    let mut event_loop = unwrap!(Core::new());
    // generate random unique ID for this node
    let service_id: PeerId = rand::random();
    println!("Service id: {}", service_id);

    // does the p2p connection as demonstrated in `connect.rs` example
    let peer = connect_to_peer(&mut event_loop, service_id);
    println!(
        "Connected to peer: {}, {}",
        peer.uid(),
        unwrap!(peer.addr())
    );

    let (peer_sink, peer_stream) = peer.split();
    // spawn an asynchronous task that handles incoming data
    event_loop.handle().spawn(
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
