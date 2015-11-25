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

fn wait_for_connection(receiver: &Receiver<Event>) -> Connection {
    loop {
        let event = match receiver.recv() {
            Ok(event) => event,
            Err(what) => panic!(format!("Could not connect {:?}", what)),
        };

        match event {
            crust::Event::OnConnect(c, _) => return c,
            crust::Event::OnAccept(c)  => return c,
            _ => panic!("Unexpected event"),
        }
    }
}

#[bench]
fn send_random_data(b: &mut Bencher) {
    let (s1_tx, s1_rx) = channel();
    let mut s1 = Service::new_inactive(s1_tx).unwrap();

    let s1_endpoint = match s1.start_accepting(Port::Tcp(0)) {
        Ok(ep) => ep,
        Err(_) => panic!("Failed to start Service #1"),
    };

    let (s2_tx, s2_rx) = channel();
    let s2 = Service::new_inactive(s2_tx).unwrap();

    s2.connect(0, vec![s1_endpoint]);

    let _s2_ep = wait_for_connection(&s1_rx);
    let s1_ep = wait_for_connection(&s2_rx);

    let data = generate_random_vec_u8(1024 * 1024);
    let data_len = data.len();

    b.iter(move || {
        s2.send(s1_ep.clone(), data.clone());

        loop {
            let event = match s1_rx.recv() {
                Ok(event) => event,
                Err(_)    => panic!("Service #1 closed connection"),
            };

            match event {
                crust::Event::NewMessage(_, _bytes) => {
                    break;
                },
                crust::Event::LostConnection(_) => {
                    break;
                },
                _ => {
                    panic!("Unexpected event: {:?}", event);
                },
            }
        }
    });

    b.bytes = data_len as u64;
}

