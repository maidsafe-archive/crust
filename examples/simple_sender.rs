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
#![deny(deprecated, drop_with_repr_extern, improper_ctypes,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]

#[macro_use]
extern crate env_logger;
extern crate crust;
#[macro_use] extern crate maidsafe_utilities;

fn main() {
    match env_logger::init() {
        Ok(()) => {},
        Err(e) => println!("Error initialising logger; continuing without: {:?}", e)
    }

    // The Service will probably create a "user app directory" (see the docs for
    // `FileHandler::write_file()`).  This object will try to clean up this directory when it goes
    // out of scope.  Normally apps would not do this - this directory will hold the peristent cache
    // files.
    let _cleaner = ::crust::ScopedUserAppDirRemover;

    // We receive events (e.g. new connection, message received) from the Service via an
    // asynchronous channel.
    let (category_tx, _) = ::std::sync::mpsc::channel();
    let (channel_sender, channel_receiver) = ::std::sync::mpsc::channel();

    let crust_event_category = ::maidsafe_utilities::event_sender::RoutingEventCategory::CrustEvent;
    let event_sender = ::maidsafe_utilities::event_sender::RoutingObserver::new(channel_sender,
                                                                                crust_event_category,
                                                                                category_tx);

    let mut service = ::crust::Service::new(event_sender).unwrap();

    let (bs_sender, bs_receiver) = ::std::sync::mpsc::channel();
    // Start a thread running a loop which will receive and display responses from the peer.
    let _ = ::std::thread::Builder::new().name("SimpleSender event handler".to_string()).spawn(move || {
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
                crust::Event::OnConnect(Ok(endpoint), _) => {
                    println!("Connected to {:?}", endpoint);
                    let _ = bs_sender.send(endpoint);
                },
                crust::Event::OnAccept(endpoint) => {
                    println!("Accepted {:?}", endpoint);
                    let _ = bs_sender.send(endpoint);
                },
                _ => (),
            }
        }
        println!("Stopped receiving.");
    });

    service.bootstrap(0, None);

    println!("Service trying to bootstrap off node listening on TCP port 8888 \
              and UDP broadcast port 5484");

    // Block until bootstrapped
    let peer_endpoint = match bs_receiver.recv() {
        Ok(endpoint) => endpoint,
        Err(e) => {
            println!("SimpleSender event handler closed; error : {}", e);
            ::std::process::exit(1);
        },
    };

    println!("New bootstrap connection made to {:?}", peer_endpoint);

    // Send all the numbers from 0 to 12 inclusive.  Expect to receive replies containing the
    // Fibonacci number for each value.
    for value in 0u8..13u8 {
        service.send(peer_endpoint.clone(), value.to_string().into_bytes());
    }

    // Allow the peer time to process the requests and reply.
    ::std::thread::sleep(::std::time::Duration::from_secs(2));
}
