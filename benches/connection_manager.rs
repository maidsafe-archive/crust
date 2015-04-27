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
use std::sync::mpsc::{channel};

#[bench]
fn connection_manager_start(b: &mut Bencher) {
  b.iter(|| {
    println!("-----------------");
    let (cm_tx, _) = channel();
    let mut cm = ConnectionManager::new(cm_tx);
    let cm_addr =  match cm.start_listening(vec![Port::Tcp(5483)], None) {
      Ok(eps) => {
            println!("main listening on {} ",
                     match eps[0].clone() { Endpoint::Tcp(socket_addr) => { socket_addr } });
            eps[0].clone()
          },
      Err(_) => panic!("main connection manager start_listening failure")
    };

    {
      let (cm_aux_tx, _) = channel();
      let mut cm_aux = ConnectionManager::new(cm_aux_tx);
      let cm_aux_addr = match cm_aux.start_listening(vec![Port::Tcp(5483)], None) {
        Ok(eps) => {
              println!("aux listening on {} ",
                       match eps[0].clone() { Endpoint::Tcp(socket_addr) => { socket_addr } });
              eps[0].clone()
            },
        Err(_) => panic!("main connection manager start_listening failure")
      };

      cm.connect(vec![cm_aux_addr.clone()]);
      println!("main: connected main to aux");
      spawn(move ||{
        cm_aux.connect(vec![cm_addr]);
        println!("aux: connected aux to main");
      }).join();
    }

  });
}

