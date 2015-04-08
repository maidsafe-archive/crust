// Copyright 2014-2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

#![feature(test)]
extern crate crust;
extern crate test;

use std::sync::mpsc;
use std::sync::mpsc::{Receiver};
use std::io::Result as IoResult;
use std::str::FromStr;
use test::Bencher;

use crust::tcp_connections::{OutTcpStream};

#[bench]
fn bench_number_of_packets(b: &mut Bencher) {
  b.iter(|| {
    let (i, mut o) : IoResult<(Receiver<I>, OutTcpStream<O>)> = crust::tcp_connections::connect_tcp(std::net::SocketAddr::from_str("127.0.0.1:5483").unwrap());
    for x in 0..10 {
      o.send(&x).ok();
    }
    o.close();
    for a in i.iter() {
        let (x, fx): (u64, u64) = a;
        println!("{} -> {}", x, fx);
    }
  });
}
