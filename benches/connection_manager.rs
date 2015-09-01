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

use std::sync::mpsc::{channel, Receiver};

pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}

fn wait_for_connection(receiver: &Receiver<Event>) -> Endpoint{
    loop {
        let event = match receiver.recv() {
            Ok(event) => event,
            Err(what) => panic!(format!("Could not connect {:?}", what)),
        };

        match event {
            crust::Event::NewConnection(ep)          => return ep,
            crust::Event::NewBootstrapConnection(ep) => return ep,
            _ => panic!("Unexpected event"),
        }
    }
}

#[bench]
fn send_random_data(b: &mut Bencher) {
    let (cm1_tx, cm1_rx) = channel();
    let mut cm1 = ConnectionManager::new(cm1_tx).unwrap();
    cm1.bootstrap(1);

    std::thread::sleep_ms(100);

    let (cm2_tx, cm2_rx) = channel();
    let mut cm2 = ConnectionManager::new(cm2_tx).unwrap();
    cm2.bootstrap(1);

    let _cm2_ep = wait_for_connection(&cm1_rx);
    let cm1_ep = wait_for_connection(&cm2_rx);

    let data = generate_random_vec_u8(1024 * 1024);
    let data_len = data.len();

    b.iter(move || {
        if let Err(what) = cm2.send(cm1_ep.clone(), data.clone()) {
            panic!(format!("ConnectionManager #2 failed to send data: {:?}", what));
        }

        loop {
            let event = match cm1_rx.recv() {
                Ok(event) => event,
                Err(_)    => panic!("ConnectionManager #1 closed connection"),
            };

            match event {
                crust::Event::NewMessage(_endpoint, _bytes) => {
                    break;
                },
                crust::Event::NewBootstrapConnection(_endpoint) => {
                    panic!("Unexpected event: NewBootstrapConnection");
                },
                crust::Event::NewConnection(_endpoint) => {
                    panic!("Unexpected event: NewConnection");
                },
                crust::Event::LostConnection(_endpoint) => {
                    break;
                }
            }
        }
    });

    b.bytes = data_len as u64;
}

