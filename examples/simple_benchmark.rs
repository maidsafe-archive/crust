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

//! Example which runs a Crust node.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]

#[macro_use]
extern crate docopt;
extern crate rand;
extern crate crust;
extern crate time;
extern crate sodiumoxide;
extern crate rustc_serialize;
#[macro_use]
extern crate maidsafe_utilities;

use rand::distributions::IndependentSample;
use docopt::Docopt;
use std::sync::mpsc::{self, Receiver};
use rustc_serialize::Decoder;
use sodiumoxide::crypto::sign::PublicKey;
use crust::{Connection, Event, Service};
use maidsafe_utilities::event_sender;


fn timed<F>(f: F) -> f64
    where F: FnOnce()
{
    let start = time::precise_time_s();
    f();
    let end = time::precise_time_s();
    end - start
}

fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    (0..size).map(|_| rand::random()).collect()
}

fn generate_random_port() -> u16 {
    let mut rng = rand::thread_rng();
    let range = rand::distributions::Range::new(1024, 65535);
    range.ind_sample(&mut rng)
}

fn wait_for_bootstrap_finished(receiver: &Receiver<Event>,
                               category_rx: &Receiver<event_sender::MaidSafeEventCategory>) {
    loop {
        for it in category_rx.iter() {
            match it {
                event_sender::MaidSafeEventCategory::CrustEvent => {
                    if let Ok(event) = receiver.try_recv() {
                        match event {
                            Event::BootstrapFinished => return,
                            _ => panic!("Unexpected event."),
                        }
                    } else {
                        panic!("Error occurred during bootstrap.");
                    }
                }
                _ => unreachable!("This event category should not have been fired - {:?}.", it),
            }
        }
    }
}

fn wait_for_connection(receiver: &Receiver<Event>,
                       category_rx: &Receiver<event_sender::MaidSafeEventCategory>) -> (Connection, PublicKey) {
    loop {
        for it in category_rx.iter() {
            match it {
                event_sender::MaidSafeEventCategory::CrustEvent => {
                    if let Ok(event) = receiver.try_recv() {
                        match event {
                            Event::NewConnection { connection: Ok(connection), their_pub_key: pub_key } => {
                                return (connection, pub_key)
                            }
                            _ => panic!("Unexpected event"),
                        }
                    } else {
                        panic!("Failed to connect");
                    }
                }
                _ => unreachable!("This event category should not have been fired - {:?}", it),
            }
        }
    }
}

#[derive(RustcDecodable, Debug)]
struct Args {
    flag_chunk_size: Option<u64>,
    flag_n_exchanges: Option<u64>,
}

static USAGE: &'static str = "
Usage:
  simple_benchmark [options]

The benchmark will create two \
                              services and exchange messages using TCP into one
direction.

You \
                              can specify the number of messages exchanged and the length of each \
                              message.

Options:
  -s SIZE, --chunk-size=SIZE             The \
                              size of each message sent in bytes.
  -n EXCHANGES, \
                              --n-exchanges=EXCHANGES  How many messages should be sent.
  -h, \
                              --help                             Display this help message.
";

fn main() {
    let args: Args = Docopt::new(USAGE)
                         .and_then(|docopt| docopt.decode())
                         .unwrap();
    let port = generate_random_port();
    let (category_tx, category_rx) = mpsc::channel();
    let crust_event_category = event_sender::MaidSafeEventCategory::CrustEvent;
    let (s1_tx, s1_rx) = mpsc::channel();
    let event_sender0 = event_sender::MaidSafeObserver::new(s1_tx, crust_event_category.clone(), category_tx.clone());
    let s1 = unwrap_result!(Service::new(event_sender0, port));

    wait_for_bootstrap_finished(&s1_rx, &category_rx);

    assert!(s1.set_listen_for_peers(true));

    let (s2_tx, s2_rx) = mpsc::channel();
    let event_sender1 = event_sender::MaidSafeObserver::new(s2_tx, crust_event_category, category_tx);
    let _s2 = unwrap_result!(Service::new(event_sender1, port));
    let (mut s2_s1_connection, _s1_pub_key) = wait_for_connection(&s2_rx, &category_rx);

    wait_for_bootstrap_finished(&s2_rx, &category_rx);

    let (_s1_s2_connection, _s2_pub_key) = wait_for_connection(&s1_rx, &category_rx);
    let chunk_size = args.flag_chunk_size.unwrap_or(1024 * 1024);
    let chunk = generate_random_vec_u8(chunk_size as usize);
    let n_exchanges = args.flag_n_exchanges.unwrap_or(3);
    let bytes = chunk_size * n_exchanges;

    let elapsed = timed(move || {
        let mut i = 0;
        while i != n_exchanges {
            unwrap_result!(s2_s1_connection.send(&chunk.clone()[..]));
            loop {
                match s1_rx.recv() {
                    Ok(crust::Event::NewMessage(_pub_key, ref msg)) => {
                        assert_eq!(*msg, chunk.clone());
                        break;
                    },
                    Ok(e) => panic!("Unexpected event: {:?}", e),
                    Err(_) => panic!("Channel closed"),
                }
            }
            i += 1;
        }
    });

    println!("Throughput: {} bytes/second", bytes as f64 / elapsed);
}
