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

extern crate crust;
use std::str::FromStr;

fn main() {
    // incoming: (u64, u64)
    // outgoing: u64
    let (incoming_channel, mut outgoing_channel) = crust::tcp_connections::connect_tcp(
        std::net::SocketAddr::from_str("127.0.0.1:9999").unwrap()).unwrap();

    // Send all the numbers from 0 to 10.
    for value in (0u64..10u64) {
        outgoing_channel.send(&value).ok();
    }

    // Close our outgoing channel. This is necessary because otherwise, the receiver will keep
    // waiting for this sender to send it data and we will deadlock.
    outgoing_channel.close();

    // Print everything that we get back.
    for response in incoming_channel.iter() {
        let (original_value, fibonacci_result): (u64, u64) = response;
        println!("{} -> {}", original_value, fibonacci_result);
    }
}
