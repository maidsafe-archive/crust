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

#![forbid(warnings)]
#![deny(bad_style, deprecated, drop_with_repr_extern, improper_ctypes, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints,
        unsafe_code, unsigned_negation, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

extern crate crust;
extern crate tempdir;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::thread;
use std::path::PathBuf;
use tempdir::TempDir;

use crust::{ConnectionManager, Endpoint, write_config_file};

// TODO update to take listening port once api is updated
fn make_temp_config(beacon_port: Option<u16>) -> (PathBuf, TempDir) {
    let temp_dir = TempDir::new("crust_peer").unwrap();
    let mut config_file_path = temp_dir.path().to_path_buf();
    config_file_path.push("simple_sender.config");

    let _ = write_config_file(Some(config_file_path.clone()),
                              None,
                              None,
                              None,
                              beacon_port,
                             ).unwrap();
    (config_file_path, temp_dir)
}

fn main() {
    let temp_config = make_temp_config(Some(9999));
    // We receive events (e.g. new connection, message received) from the ConnectionManager via an
    // asynchronous channel.
    let (channel_sender, channel_receiver) = channel();
    let connection_manager = ConnectionManager::new(channel_sender, Some(temp_config.0.clone()));

    // Start a thread running a loop which will receive and display responses from the peer.
    let _ = thread::Builder::new().name("SimpleSender event handler".to_string()).spawn(move || {
        // Receive the next event
        while let Ok(event) = channel_receiver.recv() {
            // Handle the event
            match event {
                crust::Event::NewMessage(endpoint, bytes) => {
                    match String::from_utf8(bytes) {
                        Ok(reply) => println!("Peer on {:?} replied with \"{}\"", endpoint, reply),
                        Err(why) => {
                            println!("Error receiving message: {}", why);
                            continue
                        },
                    }
                },
                crust::Event::NewConnection(endpoint) => {
                    println!("New connection made to {:?}", endpoint);
                },
                _ => (),
            }
        }
        println!("Stopped receiving.");
    });

    // Try to connect to "simple_receiver" example node which should be listening on TCP port 8888
    // and for UDP broadcasts (beacon) on 9999.
    let receiver_listening_endpoint =
        Endpoint::Tcp(SocketAddr::from_str(&"127.0.0.1:8888").unwrap());
    let peer_endpoint = match connection_manager.bootstrap(Some(vec![receiver_listening_endpoint]),
                                                           Some(9999)) {
        Ok(endpoint) => endpoint,
        Err(why) => {
            println!("ConnectionManager failed to bootstrap off node listening on TCP port 8888 \
                     and UDP broadcast port 9999: {}.", why);
            println!("This example needs the \"simple_receiver\" example to be running first on \
                     this same machine.");
            std::process::exit(1);
        }
    };

    // Send all the numbers from 0 to 12 inclusive.  Expect to receive replies containing the
    // Fibonacci number for each value.
    for value in (0u8..13u8) {
        if let Err(why) = connection_manager.send(peer_endpoint.clone(), value.to_string().into_bytes()) {
            println!("Failed to send {} to {:?}: {}", value, peer_endpoint, why)
        }
    }

    // Allow the peer time to process the requests and reply.
    thread::sleep_ms(2000);
}
