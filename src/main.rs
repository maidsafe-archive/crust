#![allow(unused)]

extern crate mio;
#[macro_use]
extern crate maidsafe_utilities;
extern crate rand;

use std::str::FromStr;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;
use std::sync::mpsc;
use std::net::TcpListener;
use std::io::{Read, Write};
use service::{Service, CrustMsg};
use maidsafe_utilities::thread::RaiiThreadJoiner;

mod service;
mod state;
mod core;
mod connection_states;

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

    let (tx, rx) = mpsc::channel();

    let mut service = Service::new(tx);

    println!("Connecting ...");
    service.connect(SocketAddr::from_str("127.0.0.1:33333").expect("Require proper address"));

    for it in rx.iter() {
        match it {
            CrustMsg::NewConnection(peer_id) => {
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
            CrustMsg::NewMessage(peer_id, msg) => {
                println!("Routing received from peer id {}: {:?}", peer_id, msg);
                break;
            }
        }
    }

    println!("\n------------------------------------------------------\n\n");
}
