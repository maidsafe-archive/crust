// Copyright 2016 MaidSafe.net limited.
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
#[macro_use]
extern crate maidsafe_utilities;

use crust::{CrustEventSender, Event, Service};
use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};

// Number of nodes that will be sending messages to the receiving node.
const NUM_SENDERS: usize = 5;

// Number of messages each sending node tries to send.
const NUM_MESSAGES_PER_SENDER: usize = 1000;

#[test]
fn sent_messages_are_received() {
    let receiver_handle = spawn_receiving_node(NUM_SENDERS);

    let sender_handles = (0..NUM_SENDERS)
                             .map(|_| spawn_sending_node())
                             .collect::<Vec<_>>();

    let sent_messages = sender_handles.into_iter()
                                      .map(|handle| handle.join().unwrap())
                                      .fold(0, |sum, value| sum + value);

    let received_messages = receiver_handle.join().unwrap();

    assert_eq!(sent_messages, received_messages);
}

fn spawn_receiving_node(expected_connections: usize) -> JoinHandle<usize> {
    let (event_sender, category_rx, event_rx) = create_event_sender();
    let mut service = unwrap_result!(Service::new(event_sender));

    service.start_service_discovery();
    let _ = unwrap_result!(service.start_listening_tcp());
    let _ = unwrap_result!(service.start_listening_utp());

    // Wait for BootstrapFinished so we know this node is already listening when
    // this function returns.
    handle_events(&category_rx, &event_rx, |event| {
        match event {
            Event::BootstrapFinished => false,
            _ => true,
        }
    });

    thread::spawn(move || {
        let mut num_connects = 0;
        let mut num_disconnects = 0;
        let mut num_messages = 0;

        // We need to move the service into this thread, even if we don't need to
        // do anything with it.
        let _ = service;

        handle_events(&category_rx, &event_rx, |event| {
            match event {
                Event::BootstrapAccept(..) => {
                    num_connects += 1;
                }

                Event::LostPeer(..) => {
                    num_disconnects += 1;
                }

                Event::NewMessage(..) => {
                    num_messages += 1;
                }

                _ => (),
            }

            num_connects < expected_connections || num_disconnects < expected_connections
        });

        num_messages
    })
}

fn spawn_sending_node() -> JoinHandle<usize> {
    thread::spawn(move || {
        let (event_sender, category_rx, event_rx) = create_event_sender();
        let service = unwrap_result!(Service::new(event_sender));

        let message = vec![255];
        let mut num_messages = 0;

        handle_events(&category_rx, &event_rx, |event| {
            match event {
                Event::BootstrapConnect(peer_id) => {
                    for _ in 0..NUM_MESSAGES_PER_SENDER {
                        let _ = unwrap_result!(service.send(&peer_id, message.clone()));
                        num_messages += 1;
                        thread::yield_now();
                    }

                    false
                }

                _ => true
            }
        });

        num_messages
    })
}

fn create_event_sender()
    -> (CrustEventSender,
        Receiver<MaidSafeEventCategory>,
        Receiver<Event>)
{
    let (category_tx, category_rx) = mpsc::channel();
    let event_category = MaidSafeEventCategory::Crust;
    let (event_tx, event_rx) = mpsc::channel();

    (MaidSafeObserver::new(event_tx, event_category, category_tx),
     category_rx,
     event_rx)
}

// Call the given lambda for each event received. If the lambda returns false,
// the processing stops. Otherwise it continues.
fn handle_events<F>(category_rx: &Receiver<MaidSafeEventCategory>,
                    event_rx: &Receiver<Event>,
                    mut f: F)
    where F: FnMut(Event) -> bool
{
    for category in category_rx.iter() {
        match category {
            MaidSafeEventCategory::Crust => {
                if let Ok(event) = event_rx.try_recv() {
                    if !f(event) {
                        break;
                    }
                }
            }

            _ => unreachable!("Unexpected event category {:?}", category),
        }
    }
}
