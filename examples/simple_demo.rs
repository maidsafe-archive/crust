// Copyright 2016 MaidSafe.net limited.
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

//! Simple receiver example.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]

extern crate crust;
#[macro_use]
extern crate maidsafe_utilities;
extern crate rand;
extern crate socket_addr;

use socket_addr::SocketAddr;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use crust::{CrustEventSender, Event, MAX_DATA_LEN, Service, StaticContactInfo};
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use rand::Rng;

type StdSocketAddr = std::net::SocketAddr;

fn spawn_test_server() {
    let ls = TcpListener::bind("127.0.0.1:33333").expect("Could not bind listener.");
    let (mut strm, _) = ls.accept().expect("Error in accepting");
    loop {
        let mut buf = [0; 14];
        if strm.read_exact(&mut buf).is_err() {
            // Graceful exit in this case
            break;
        }
        println!("Test peer received {:?}", buf);
        let mut reply : Vec<u8> = vec![0x04, 0x00, 0x00, 0x00,
                                       0x11, 0x22, 0x33, 0x44,
                                       0x04, 0x00, 0x00, 0x00,
                                       0xAA, 0xBB, 0xCC, 0xDD,
                                       0x01, 0x00, 0x20, 0x00];
        strm.write_all(&mut reply).expect("Error in writing");
    }
}

/// utility to create random vec u8 of a given size
pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    rand::thread_rng().gen_iter().take(size).collect()
}

fn main() {
    println!("\n\n-------- Running Routing ----------\n");

    let _raii_joiner = RaiiThreadJoiner::new(thread!("TestPeer", move || {
        spawn_test_server();
    }));
    thread::sleep(Duration::from_millis(300));

    let (crust_tx, crust_rx) = mpsc::channel();
    let (category_tx, _) = mpsc::channel();
    let crust_event_category = MaidSafeEventCategory::Crust;
    let crust_sender = CrustEventSender::new(crust_tx,
                                             crust_event_category,
                                             category_tx);
    let mut service = Service::new(crust_sender).expect("Failed constructing crust service");

    println!("Connecting ...");
    let contact_info = StaticContactInfo {
        tcp_acceptors: vec![SocketAddr(StdSocketAddr::from_str("127.0.0.1:33333").expect("Require proper address"))],
        tcp_mapper_servers: vec![],
    };

    let _ = service.direct_connect(contact_info).expect("Failed to connect");

    for it in crust_rx.iter() {
        match it {
            Event::NewPeer(Ok(()), peer_id) => {
                println!("Routing received new connection with peer id {}", peer_id);
                service.send(peer_id, generate_random_vec_u8(MAX_DATA_LEN as usize + 1))
                       .expect("Failed to send data");
            }
            Event::NewMessage(peer_id, msg) => {
                println!("Routing received from peer id {}: {:?}", peer_id, msg);
            }
            Event::LostPeer(peer_id) => {
                println!("Lost Peer {}", peer_id);
                break;
            }
            _ => {
                println!("Unexpected event notification");
                break;
            }
        }
    }

    println!("\n------------------------------------------------------\n\n");
}
