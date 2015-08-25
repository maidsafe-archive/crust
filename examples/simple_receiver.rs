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
        unsafe_code, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

#[macro_use]
extern crate env_logger;
extern crate crust;

fn fibonacci_number(n: u64) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        n => fibonacci_number(n - 1) + fibonacci_number(n - 2)
    }
}

// TODO - Once Rust gets signal-handling (https://github.com/rust-lang/rust/issues/11203) we should
// catch ctrl+C signals here to allow the server to exit gracefully.  This will allow the
// ScopedUserAppDirRemover to remove the user app dir.
fn main() {
    use std::str::FromStr;
    match env_logger::init() {
        Ok(()) => {},
        Err(e) => println!("Error initialising logger; continuing without: {:?}", e)
    }

    // The ConnectionManager will probably create a "user app directory" (see the docs for
    // `FileHandler::write_file()`).  This object will try to clean up this directory when it goes
    // out of scope.  Normally apps would not do this - this directory will hold the peristent cache
    // files.
    let _cleaner = ::crust::ScopedUserAppDirRemover;

    // We receive events (e.g. new connection, message received) from the ConnectionManager via an
    // asynchronous channel.
    let (channel_sender, channel_receiver) = ::std::sync::mpsc::channel();
    let mut connection_manager = ::crust::ConnectionManager::new(channel_sender);

    // Start listening.  Try to listen on port 8888 for TCP and for UDP broadcasts (beacon) on
    // default port 5483.
    let listening_endpoints =
        match connection_manager.start_accepting(vec![::crust::Port::Tcp(8888u16)]) {
            Ok(endpoints) => endpoints,
            Err(why) => {
                println!("ConnectionManager failed to start listening on TCP port 8888: {}", why);
                ::std::process::exit(1);
            }
        };

    print!("Listening for new connections on ");
    for endpoint in &listening_endpoints {
        print!("{:?}, ", *endpoint);
    };
    println!("Run the simple_sender example in another terminal to send messages to this node.");

    // Receive the next event
    while let Ok(event) = channel_receiver.recv() {
        // Handle the event
        match event {
            crust::Event::NewMessage(endpoint, bytes) => {
                // For this example, we only expect to receive encoded `u8`s
                let requested_value = match String::from_utf8(bytes) {
                    Ok(message) => {
                        match u8::from_str(&message) {
                            Ok(value) => value,
                            Err(why) => {
                                println!("Error parsing message: {}", why);
                                continue;
                            },
                        }
                    },
                    Err(why) => {
                        println!("Error receiving message: {}", why);
                        continue;
                    },
                };

                // Calculate the Fibonacci number for the requested value and respond with that
                let fibonacci_result = fibonacci_number(requested_value as u64);
                println!("Received \"{}\" from {:?} - replying with \"{}\"", requested_value,
                         endpoint, fibonacci_result);
                let response =
                    format!("The Fibonacci number for {} is {}", requested_value, fibonacci_result);
                if let Err(why) = connection_manager.send(endpoint.clone(), response.into_bytes()) {
                    println!("Failed to send reply to {:?}: {}", endpoint, why)
                }
            },
            crust::Event::NewConnection(endpoint) => {
                println!("New connection made to {:?}", endpoint);
            },
            crust::Event::LostConnection(endpoint) => {
                println!("Lost connection to {:?}", endpoint);
            },
            crust::Event::NewBootstrapConnection(endpoint) => {
                println!("New Bootstrap connection made to {:?}", endpoint);
            }
        }
    }
    println!("Stopped receiving.");
}
