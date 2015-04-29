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

#![feature(test)]
extern crate crust;
extern crate rand;
extern crate test;

use rand::random;
use test::Bencher;
use crust::*;

use std::sync::mpsc::{channel};
use std::net::SocketAddr;
use std::str::FromStr;

pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}

#[bench]
fn connection_manager_start(b: &mut Bencher) {
  // println!("------------------------------------------");
    let (cm_tx, cm_rx) = channel();
    let mut cm = ConnectionManager::new(cm_tx);
    let mut cm_listen_port : u16 = 5483;
    let mut cm_addr = Endpoint::Tcp(SocketAddr::from_str(&"127.0.0.1:0").unwrap());
    match cm.start_listening(vec![Port::Tcp(cm_listen_port)], None) {
      Ok(result) => {
            if result.0.len() > 0 {                
                match result.0[0].clone() {
                  Endpoint::Tcp(socket_addr) => {
                    cm_listen_port = socket_addr.port();
                    // println!("main listening on {} ", socket_addr);
                  }
                }
                cm_addr = result.0[0].clone();
            } else {
                panic!("main connection manager start_listening none listening port returned");
            }
          }
      Err(_) => panic!("main connection manager start_listening failure")
    };

  std::thread::sleep_ms(100);

  let (cm_aux_tx, _) = channel();
  let mut cm_aux = ConnectionManager::new(cm_aux_tx);
  match cm_aux.start_listening(vec![Port::Tcp(cm_listen_port - 10)], None) {
    Ok(result) => {
        if result.0.len() > 0 {
            // println!("aux listening on {} ",
            //          match result.0[0].clone() { Endpoint::Tcp(socket_addr) => { socket_addr } });
        } else {
            // panic!("aux connection manager start_listening none listening port returned");
        }
      },
    Err(_) => { println!("aux connection manager start_listening failure -- print");
                panic!("aux connection manager start_listening failure");
              }
  };

  cm_aux.connect(vec![cm_addr.clone()]);
  let data = generate_random_vec_u8(1024 * 1024);
  b.iter(move || {
      let _ = cm_aux.send(cm_addr.clone(), data.clone());
      loop {
          let event = cm_rx.recv();
          // println!("received an event");
          if event.is_err() {
            println!("stop listening");
            break;
          }
          match event.unwrap() {
              crust::Event::NewMessage(endpoint, bytes) => {
                  // println!("received from {} with a new message of length : {}",
                  //          match endpoint { Endpoint::Tcp(socket_addr) => socket_addr }, bytes.len());
                           // match String::from_utf8(bytes) { Ok(msg) => msg,
                           //                                  Err(_) => "unknown msg".to_string() });
                  break;
              },
              crust::Event::NewConnection(endpoint) => {
                  // println!("adding new node:{}", match endpoint { Endpoint::Tcp(socket_addr) => socket_addr });
              },
              crust::Event::LostConnection(endpoint) => {
                  // println!("dropping node:{}", match endpoint { Endpoint::Tcp(socket_addr) => socket_addr });
                  break;
              }
          }
      }
  });
  b.bytes = 1024 * 1024;
}

