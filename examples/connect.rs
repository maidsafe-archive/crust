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

//! This example demonstrates how to make connection using `crust`.  We are using `crust::Service`
//! to listen for incoming connections and to establish connection to remote peer.
//!
//! In a nutshell connetion looks like this:
//!
//! 1. start listening for incoming connections
//! 2. prepare connection information: public and private
//! 3. exchange public information
//! 4. connect
//!
//! Run two instances of this sample: preferably on separate computers but localhost is fine too.
//! When the sample starts it prints generated public information which is represented as JSON
//! object.  Copy this object from first to second peer and hit ENTER.  Do the same with the second
//! peer: copy it's public information JSON to first peer and hit ENTER.
//! On both peers you should see something like:
//! ```
//! Connected to peer: 4a755684f72fe63fba86725b80d42d69ed649392
//! ```
//! That's it, it means we successfully did a peer-to-peer connection.

extern crate clap;
extern crate future_utils;
extern crate futures;
extern crate rand;
#[macro_use]
extern crate rand_derive;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;
extern crate void;

extern crate crust;

mod utils;

use clap::App;
use crust::{ConfigFile, Service};
use future_utils::bi_channel;
use futures::future::{empty, Future};
use futures::Stream;
use rand::Rng;
use tokio_core::reactor::Core;
use utils::PeerId;

fn main() {
    let _ = App::new("Crust basic connection example")
        .about(
            "Attempts to connect to remote peer given its connection information. \
             Start two instances of this example. Each instance generates and prints its \
             connection information to stdout in JSON format. You have to manually copy/paste \
             this info from one instance to the other and hit ENTER to start connection.",
        )
        .get_matches();

    let mut event_loop = unwrap!(Core::new());
    let handle = event_loop.handle();
    let service_id = rand::thread_rng().gen::<PeerId>();
    println!("Service id: {}", service_id);

    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![
        unwrap!("tcp://0.0.0.0:0".parse()),
        unwrap!("utp://0.0.0.0:0".parse()),
    ];
    let make_service = Service::with_config(&event_loop.handle(), config, service_id);
    let service = unwrap!(
        event_loop.run(make_service),
        "Failed to create Service object",
    );

    let listeners = unwrap!(
        event_loop.run(service.start_listening().collect()),
        "Failed to start listening to peers",
    );
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
        "Connected to peer: {} - {}",
        peer.uid(),
        unwrap!(peer.addr())
    );

    // Run event loop forever.
    let res = event_loop.run(empty::<(), ()>());
    unwrap!(res);
}
