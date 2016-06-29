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
#![cfg_attr(feature="clippy", allow(use_debug))]

#![feature(test)]
extern crate crust;
#[macro_use]
extern crate maidsafe_utilities;
extern crate rand;
extern crate test;
#[allow(unused_extern_crates)]
#[macro_use]
extern crate unwrap;

use rand::random;
use test::Bencher;
use crust::*;
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use maidsafe_utilities::log::init;

use std::sync::mpsc::{channel, Receiver};

pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}

fn wait_for_connection(category_receiver: &Receiver<MaidSafeEventCategory>,
                       crust_receiver: &Receiver<Event>) -> Connection {
    match unwrap!(category_receiver.recv()) {
        MaidSafeEventCategory::CrustEvent => {
            let event = match crust_receiver.recv() {
                Ok(event) => event,
                Err(what) => panic!(format!("Could not connect {:?}", what)),
            };

            match event {
                crust::Event::OnConnect(Ok((_endpoint, connection)), _token) => return connection,
                crust::Event::OnAccept(_endpoint, connection)  => return connection,
                _ => panic!("Unexpected event"),
            }
        },
        _ => panic!("Unexpected event"),
    }
}

#[bench]
fn send_random_data(b: &mut Bencher) {
    init(true);
    let (s1_tx, s1_rx) = channel();
    let (category1_tx, category1_rx) = ::std::sync::mpsc::channel();
    let crust_event_category = MaidSafeEventCategory::CrustEvent;
    let event_sender1 = CrustEventSender::new(s1_tx, crust_event_category.clone(), category1_tx);
    let mut s1 = unwrap!(Service::new(event_sender1));

    let s1_endpoint = match s1.start_accepting(Port::Tcp(0)) {
        Ok(ep) => ep,
        Err(_) => panic!("Failed to start Service #1"),
    };

    let (s2_tx, s2_rx) = channel();
    let (category2_tx, category2_rx) = ::std::sync::mpsc::channel();
    let event_sender2 = CrustEventSender::new(s2_tx, crust_event_category, category2_tx);
    let s2 = unwrap!(Service::new(event_sender2));

    s2.connect(0, vec![s1_endpoint]);

    let _s2_ep = wait_for_connection(&category1_rx, &s1_rx);
    let s1_ep = wait_for_connection(&category2_rx, &s2_rx);

    let data = generate_random_vec_u8(1024 * 1024);
    let data_len = data.len();

    b.iter(move || {
        s2.send(s1_ep.clone(), data.clone());

        loop {
            let event = match s1_rx.recv() {
                Ok(event) => event,
                Err(_)    => panic!("Service #1 closed connection"),
            };

            match event {
                crust::Event::NewMessage(_, _bytes) => {
                    break;
                },
                crust::Event::LostPeer(_) => {
                    break;
                },
                _ => {
                    panic!("Unexpected event: {:?}", event);
                },
            }
        }
    });

    b.bytes = data_len as u64;
}

