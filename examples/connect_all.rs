// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! This example demonstrates `Service::connect_all()` use. This function attempts multiple
//! connections in parallel and returns the results for all attempts disregard to failures.
//! This method could be used for debugging or to collect connectivity information.

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
extern crate safe_crypto;
extern crate void;

extern crate crust;

mod utils;

use clap::App;
use crust::{ConfigFile, Service};
use future_utils::{bi_channel, FutureExt};
use futures::{stream, Future, Stream};
use safe_crypto::gen_encrypt_keypair;
use tokio_core::reactor::Core;

fn main() {
    unwrap!(env_logger::init());

    let _ = App::new("Crust connect_all() example")
        .about(
            "Attempts to connect to remote peer given its connection information. \
             Start two instances of this example. Each instance generates and prints its \
             connection information to stdout in JSON format. You have to manually copy/paste \
             this info from one instance to the other and hit ENTER to start connection.",
        ).get_matches();

    let mut event_loop = unwrap!(Core::new());
    let handle = event_loop.handle();
    let (service_pk, service_sk) = gen_encrypt_keypair();
    println!("Service public id: {:?}", service_pk);

    let config = unwrap!(ConfigFile::new_temporary());
    unwrap!(config.write()).listen_addresses = vec![
        unwrap!("tcp://0.0.0.0:0".parse()),
        unwrap!("utp://0.0.0.0:0".parse()),
    ];
    let make_service = Service::with_config(&event_loop.handle(), config, service_sk, service_pk);
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

    let connections = service.connect_all(ci_channel1).collect();
    let connections = unwrap!(event_loop.run(connections));
    println!("Connection attempts:");
    for conn in connections.iter() {
        println!("\n{:?}", conn);
    }

    let finalize_conns = stream::futures_unordered(
        connections
            .into_iter()
            .filter_map(|conn_result| conn_result.result.ok())
            .map(|peer| peer.finalize()),
    ).map_err(|e| {
        println!("Erorr to finalize the connection: {}", e);
        e
    }).for_each(|_| Ok(()))
    .then(|_| Ok(()))
    .infallible::<()>();

    unwrap!(event_loop.run(finalize_conns));
}
