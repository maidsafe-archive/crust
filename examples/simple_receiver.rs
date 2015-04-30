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

#![feature(convert, exit_status)]

extern crate crust;

use std::str::FromStr;
use std::sync::mpsc::channel;

use crust::{ConnectionManager, Port};

fn fibonacci_number(n: u64) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        n => fibonacci_number(n - 1) + fibonacci_number(n - 2)
    }
}

fn main() {
    // We receive events (e.g. new connection, message received) from the ConnectionManager via an
    // asynchronous channel.
    let (channel_sender, channel_receiver) = channel();
    let mut connection_manager = ConnectionManager::new(channel_sender);

    // Start listening.  Try to listen on port 8888 for TCP and for UDP broadcasts (beacon) on 9999.
    let listening_endpoints = match connection_manager.start_listening(vec![Port::Tcp(8888)],
                                                                        Some(9999)) {
        Ok(endpoints) => endpoints,
        Err(why) => {
            println!("ConnectionManager failed to start listening on TCP port 8888: {}", why);
            std::env::set_exit_status(1);
            return;
        }
    };

    print!("Listening for new connections on ");
    for endpoint in &listening_endpoints.0 {
        print!("{:?}, ", *endpoint);
    };
    match listening_endpoints.1 {
        Some(beacon_port) => println!("and listening for UDP broadcast on port {}.", beacon_port),
        None => println!("and not listening for UDP broadcasts."),
    };
    println!("Run the simple_sender example in another terminal to send messages to this node.");

    loop {
        // Receive the next event
        let event = channel_receiver.recv();
        if event.is_err() {
            println!("Stopped receiving.");
            break;
        }

        // Handle the event
        match event.unwrap() {
            crust::Event::NewMessage(endpoint, bytes) => {
                // For this example, we only expect to receive encoded `u8`s
                let requested_value = match String::from_utf8(bytes) {
                    Ok(message) => {
                        match u8::from_str(message.as_str()) {
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
                match connection_manager.send(endpoint.clone(), response.into_bytes()) {
                    Ok(_) => (),
                    Err(why) => println!("Failed to send reply to {:?}: {}", endpoint, why),
                }
            },
            crust::Event::NewConnection(endpoint) => {
                println!("New connection made to {:?}", endpoint);
            },
            crust::Event::LostConnection(endpoint) => {
                println!("Lost connection to {:?}", endpoint);
            }
        }
    }
}
