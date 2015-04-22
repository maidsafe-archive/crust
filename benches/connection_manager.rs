// Copyright 2015 MaidSafe.net limited
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

use test::Bencher;
use crust::*;

use std::thread::spawn;
use std::sync::mpsc::{Receiver, channel};
use std::net::{SocketAddr};
use std::str::FromStr;

#[bench]
fn connection_manager_start(b: &mut Bencher) {
  b.iter(|| {
    println!("-----------------");
    let (cm_tx, cm_rx) = channel();
    let cm = ConnectionManager::<Vec<u8>>::new(vec![1], cm_tx);
    let cm_port = cm.start_accepting().unwrap();
    println!("main: started accepting on {}", cm_port);

    let (cm_aux_tx, cm_aux_rx) = channel();
    let cm_aux = ConnectionManager::new(vec![2], cm_aux_tx);
    let cm_aux_port = cm_aux.start_accepting().unwrap();
    println!("aux: started accepting on {}", cm_aux_port);

    let addr = SocketAddr::from_str(&format!("127.0.0.1:{}", cm_aux_port)).unwrap();
    println!("main: parsed aux");
    assert!(cm.connect(addr, Vec::<u8>::new()).is_ok());
    println!("main: connected main to aux");
    spawn(move ||{
      let addr_aux = SocketAddr::from_str(&format!("127.0.0.1:{}", cm_port)).unwrap();
      println!("aux: parsed main");
      assert!(cm_aux.connect(addr_aux, Vec::<u8>::new()).is_ok());
      println!("aux: connected aux to main");
      cm_aux.stop();
      println!("aux: stopped aux");
    }).join();
    cm.stop();
    println!("main: stopped main");
  });
}

// #[bench]
// fn connection_manager(b: &mut Bencher) {
//   println!("------------ NEW ITER");
//   type Id = Vec<u8>;
//   let run_cm = |cm: ConnectionManager<Id>, o: Receiver<Event<Id>>, my_port, his_port| {
//       spawn(move ||{
//           if my_port < his_port {
//               let addr = SocketAddr::from_str(&format!("127.0.0.1:{}", his_port)).unwrap();
//               cm.connect(addr, Vec::<u8>::new());
//           }
//
//           for i in o.iter() {
//               println!("Received event {:?}", i);
//               match i {
//                   Event::Connect(_) => {
//                       println!("Connected");
//                       if cm.id() == vec![1] {
//                           assert!(cm.send(vec![2], vec![2]).is_ok());
//                       } else {
//                           assert!(cm.send(vec![1], vec![1]).is_ok());
//                       }
//                   },
//                   Event::Accept(_, _) => {
//                       println!("Accepted");
//                       if cm.id() == vec![1] {
//                           assert!(cm.send(vec![2], vec![2]).is_ok());
//                       } else {
//                           assert!(cm.send(vec![1], vec![1]).is_ok());
//                       }
//                   },
//                   Event::NewMessage(x, y) => {
//                       println!("new message !");
//                       //cm.stop();
//                       break;
//                   }
//                   _ => println!("unhandled"),
//               }
//           }
//       })
//   };
//
//   let (cm1_i, cm1_o) = channel();
//   let cm1 = ConnectionManager::new(vec![1], cm1_i);
//   let cm1_port = cm1.start_accepting().unwrap();
//
//   let (cm2_i, cm2_o) = channel();
//   let cm2 = ConnectionManager::new(vec![2], cm2_i);
//   let cm2_port = cm2.start_accepting().unwrap();
//   b.iter( move || {
//     let runner1 = run_cm(cm1, cm1_o, &cm1_port, &cm2_port);
//     let runner2 = run_cm(cm2, cm2_o, &cm2_port, &cm1_port);
//
//     assert!(runner1.join().is_ok());
//     assert!(runner2.join().is_ok());
//   });
// }
