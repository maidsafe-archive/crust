// Copyright 2015 MaidSafe.net limited
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://maidsafe.net/network-platform-licensing
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the SAFE Network Software.

extern crate crust;

use std::net::TcpListener;

fn main() {
  let tcp_listener = match TcpListener::bind("0.0.0.0:0") {
    Ok(listener) => listener,
    Err(e) => panic!("Couldn't bind to TCP socket: {}", e)
  };

  // blocking call on listen_for_broadcast
  match tcp_listener.local_addr() {
    Ok(local_addr) => crust::beacon::listen_for_broadcast(local_addr),
    Err(e) => panic!("No local address to start listening on: {}", e)
  };

  // the code below keeps the server running
  for _ in tcp_listener.incoming() {
  }
}
