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

//! Simple sender example.

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
extern crate maidsafe_utilities;
extern crate crust;

use std::thread;
use std::time::Duration;
use std::sync::mpsc::{self, Receiver};
use crust::{Connection, Event, Service};
use maidsafe_utilities::{event_sender, log};


fn wait_for_bootstrap_finished(receiver: &Receiver<Event>,
                               category_rx: &Receiver<event_sender::MaidSafeEventCategory>) {
    loop {
        for it in category_rx.iter() {
            match it {
                event_sender::MaidSafeEventCategory::CrustEvent => {
                    if let Ok(event) = receiver.recv() {
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
                       category_rx: &Receiver<event_sender::MaidSafeEventCategory>) -> Connection {
    loop {
        for it in category_rx.iter() {
            match it {
                event_sender::MaidSafeEventCategory::CrustEvent => {
                    if let Ok(event) = receiver.recv() {
                        match event {
                            Event::NewConnection { connection: Ok(connection), .. } => {
                                return connection
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

fn main() {
    log::init(true);

    let (category_tx, category_rx) = mpsc::channel();
    let event_category = event_sender::MaidSafeEventCategory::CrustEvent;
    let (service_tx, service_rx) = mpsc::channel();
    let event_sender = event_sender::MaidSafeObserver::new(service_tx, event_category.clone(), category_tx.clone());
    let service = unwrap_result!(Service::new(event_sender, 5483));
    let mut connection = wait_for_connection(&service_rx, &category_rx);

    wait_for_bootstrap_finished(&service_rx, &category_rx);
    let _ = service.set_listen_for_peers(true);

    let _ = thread!("SimpleSenderThread", move || {
        for it in category_rx.iter() {
            match it {
                event_sender::MaidSafeEventCategory::CrustEvent => {
                    if let Ok(event) = service_rx.try_recv() {
                        match event {
                            Event::NewMessage(_pub_key, bytes) => {
                                match String::from_utf8(bytes) {
                                    Ok(reply) => println!("Peer replied with \"{}\"", reply),
                                    Err(why) => {
                                        println!("Error receiving message: {}", why);
                                        continue
                                    },
                                }
                            }
                            _ => (),
                        }
                    } else {
                        break;
                    }
                },
                _ => unreachable!("This category should not have been fired - {:?}", it),
            }
        }

        println!("Stopped receiving.");
    });

    // Send all the numbers from 0 to 12 inclusive.
    // Expect to receive replies containing the Fibonacci number for each value.
    for value in 0u8..13u8 {
        let _ = unwrap_result!(connection.send(&value.to_string().into_bytes()));
    }

    // Allow the peer time to process the requests and reply.
    thread::sleep(Duration::from_secs(2));
}
