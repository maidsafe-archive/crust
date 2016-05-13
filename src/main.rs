#![allow(unused)]

#[macro_use]
extern crate maidsafe_utilities;
extern crate mio;
extern crate nat_traversal;
extern crate net2;
#[macro_use]
extern crate quick_error;
extern crate rand;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate socket_addr;

mod connection_states;
mod core;
mod error;
mod event;
mod peer_id;
mod service;
mod state;
mod static_contact_info;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use event::Event;
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use service::Service;

/// Crust Observers will be informed of crust events on this
pub type CrustEventSender = ::maidsafe_utilities::event_sender::MaidSafeObserver<Event>;

fn spawn_test_server() {
    let ls = TcpListener::bind("127.0.0.1:33333").expect("Could not bind listener.");
    let (mut strm, _) = ls.accept().expect("Error in accepting");
    loop {
        let mut buf = [0; 10];
        if strm.read_exact(&mut buf).is_err() {
            // Graceful exit in this case
            break;
        }
        println!("Test peer received {:?}", buf);
        strm.write_all(&mut buf).expect("Error in writing");
    }
}

fn main() {
    println!("\n\n-------- Running Routing ----------\n");

    let _raii_joiner = RaiiThreadJoiner::new(thread!("TestPeer", move || {
        spawn_test_server();
    }));
    thread::sleep(Duration::from_millis(300));

    let (crust_tx, crust_rx) = mpsc::channel();
    let (category_tx, category_rx) = mpsc::channel();
    let crust_event_category = MaidSafeEventCategory::Crust;
    let crust_sender = CrustEventSender::new(crust_tx,
                                             crust_event_category,
                                             category_tx);
    let mut service = Service::new(crust_sender).expect("Failed constructing crust service");

    println!("Connecting ...");
    service.connect(SocketAddr::from_str("127.0.0.1:33333").expect("Require proper address"));

    for it in crust_rx.iter() {
        match it {
            Event::NewConnection(peer_id) => {
                println!("Routing received new connection with peer id {}", peer_id);
                service.send(peer_id,
                             vec![rand::random(),
                                  rand::random(),
                                  rand::random(),
                                  rand::random(),
                                  rand::random(),
                                  rand::random(),
                                  rand::random(),
                                  rand::random(),
                                  rand::random(),
                                  rand::random()]);
            }
            Event::NewMessage(peer_id, msg) => {
                println!("Routing received from peer id {}: {:?}", peer_id, msg);
                break;
            }
            _ => {
                println!("Unexpected event notification");
                break;
            }
        }
    }

    println!("\n------------------------------------------------------\n\n");
}
