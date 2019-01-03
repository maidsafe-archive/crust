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

extern crate clap;
extern crate env_logger;
extern crate future_utils;
extern crate futures;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;
extern crate bytes;
extern crate safe_crypto;
extern crate void;

extern crate crust;

mod utils;

use bytes::{Bytes, BytesMut};
use clap::App;
use crust::{ConfigFile, Service};
use future_utils::bi_channel;
use futures::future::{empty, Future};
use futures::sink::Sink;
use futures::stream::Stream;
use safe_crypto::gen_encrypt_keypair;
use std::str;
use tokio_core::reactor::Core;

fn main() {
    unwrap!(env_logger::init());
    let _ = App::new("Crust data exchange example")
        .about(
            "Attempts to connect to remote peer given its connection information and exchange \
             messages. Start two instances of this example. Each instance generates and prints its \
             connection information to stdout in JSON format. You have to manually copy/paste this \
             info from one instance to the other and hit ENTER to start connection.",
        )
        .get_matches();

    let mut event_loop = unwrap!(Core::new());
    let handle = event_loop.handle();
    // generate random unique ID for this node
    let (service_pk, service_sk) = gen_encrypt_keypair();
    println!("Service public id: {:?}", service_pk);

    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![
        unwrap!("tcp://0.0.0.0:0".parse()),
        unwrap!("utp://0.0.0.0:0".parse()),
    ];
    let service = unwrap!(event_loop.run(Service::with_config(
        &handle,
        config,
        service_sk,
        service_pk.clone()
    )));
    let listeners = unwrap!(event_loop.run(service.start_listening().collect()));
    for listener in &listeners {
        println!("Listening on {}", listener.addr());
    }

    let (ci_channel1, ci_channel2) = bi_channel::unbounded();
    utils::exchange_conn_info(&handle, ci_channel2);
    let connect = service
        .connect(ci_channel1)
        .map(move |peer| (peer, service));
    let (peer, _service) = unwrap!(event_loop.run(connect));
    println!(
        "Connected to peer: {:?}, {}",
        peer.public_id(),
        unwrap!(peer.addr())
    );

    let (peer_sink, peer_stream) = peer.split();
    // spawn an asynchronous task that handles incoming data
    handle.spawn(
        peer_stream
            .for_each(|data: BytesMut| {
                println!("Received: {}", unwrap!(str::from_utf8(&data[..])));
                Ok(()) // keep receiving data
            })
            // adapt to Handle::spawn() requirements, see:
            // https://docs.rs/tokio-core/0.1.10/tokio_core/reactor/struct.Handle.html#method.spawn
            .then(|_| Ok(())),
    );

    // lower priority is higher, 0 is the highest.
    // Note that 0 is used for internal crust messages though.
    let hello_msg = Bytes::from(format!("Hello from peer '{:?}'!", service_pk).into_bytes());
    let bye_msg = Bytes::from(format!("Goodbye from peer '{:?}'!", service_pk).into_bytes());

    // let's send multiple messages to connected peer
    unwrap!(event_loop.run(peer_sink
        .send(hello_msg) // send first message
        .and_then(|peer_sink| { // when it's done, send the second
            // sink.send() on completion returns sink which implements Future trait
            peer_sink.send(bye_msg)
        }),));

    // Run event loop forever.
    let res = event_loop.run(empty::<(), ()>());
    unwrap!(res);
}
