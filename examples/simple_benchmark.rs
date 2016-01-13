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

#![forbid(missing_docs, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

#[macro_use]
extern crate maidsafe_utilities;
extern crate rustc_serialize;
extern crate docopt;
extern crate rand;
extern crate crust;
extern crate time;

use rand::random;
use docopt::Docopt;
use std::sync::mpsc::{channel, Receiver};
use crust::*;

fn timed<F>(f: F) -> f64 where F: FnOnce() {
    let start = time::precise_time_s();
    f();
    let end = time::precise_time_s();
    end - start
}

fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}

fn wait_for_connection(receiver: &Receiver<Event>,
                       category_rx: &::std::sync::mpsc::Receiver<::maidsafe_utilities
                                                                 ::event_sender::MaidSafeEventCategory>) -> Connection {
    loop {
        for it in category_rx.iter() {
            match it {
                ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent => {
                    if let Ok(event) = receiver.try_recv() {
                        match event {
                            crust::Event::OnConnect(Ok((_, c)), _) => return c,
                            crust::Event::OnAccept(_, c)  => return c,
                            _ => panic!("Unexpected event"),
                        }
                    } else {
                        panic!("Could not connect");
                    }
                },
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

The benchmark will create two services and exchange messages using TCP into one
direction.

You can specify the number of messages exchanged and the length of each message.

Options:
  -s SIZE, --chunk-size=SIZE             The size of each message sent in bytes.
  -n EXCHANGES, --n-exchanges=EXCHANGES  How many messages should be sent.
  -h, --help                             Display this help message.
";

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.decode())
        .unwrap();

    let (category_tx, category_rx) = ::std::sync::mpsc::channel();
    let crust_event_category = ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent;
    let (tx, s1_rx) = channel();
    let event_sender0 = ::maidsafe_utilities::event_sender::MaidSafeObserver::new(tx,
                                                                                  crust_event_category.clone(),
                                                                                  category_tx.clone());
    let mut s1 = Service::new(event_sender0).unwrap();

    let s1_ep = s1.start_accepting(0).unwrap();

    let (tx, s2_rx) = channel();
    let event_sender1 = ::maidsafe_utilities::event_sender::MaidSafeObserver::new(tx,
                                                                                  crust_event_category,
                                                                                  category_tx);
    let s2 = Service::new(event_sender1).unwrap();

    s2.connect(0, vec![s1_ep]);

    let s2_ep = wait_for_connection(&s1_rx, &category_rx);
    let _s1_ep = wait_for_connection(&s2_rx, &category_rx);

    let chunk_size = args.flag_chunk_size.unwrap_or(1024*1024);
    let chunk = generate_random_vec_u8(chunk_size as usize);
    let n_exchanges = args.flag_n_exchanges.unwrap_or(3);
    let bytes = chunk_size * n_exchanges;

    let elapsed = timed(move || {
        let mut i = 0;
        while i != n_exchanges {
            s1.send(s2_ep.clone(), chunk.clone());
            loop {
                match s2_rx.recv() {
                    Ok(crust::Event::NewMessage(_, _)) => break,
                    Ok(e) => panic!("Unexpected event: {:?}", e),
                    Err(_) => panic!("Channel closed"),
                }
            }
            i += 1;
        }
    });
    println!("Throughput: {} bytes/second", bytes as f64 / elapsed);
}
