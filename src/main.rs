extern crate mio;
#[macro_use]
extern crate maidsafe_utilities;
extern crate rand;

use std::thread;
use std::time::Duration;
use std::sync::mpsc;
use std::net::TcpListener;
use std::io::{Read, Write};
use service::{Service, CrustMsg};

mod service;
mod state;
mod core;
mod connection_states;

fn spawn_test_server() {
    let ls = TcpListener::bind("127.0.0.1:33333").expect("Could not bind listener.");
    let (strm, _) = ls.accept().expect("Error in accepting");
    loop {
        let mut buf = [0; 10];
        if let Err(e) = strm.read_exact(&mut buf) {
            println!("{:?}", e);
            break;
        }
        println!("Test peer received {:?}", buf);
        strm.write_all(&mut buf).expect("Error in writing");
    }
}

fn main() {
    spawn_test_server();

    let (tx, rx) = mpsc::channel();

    let service = Service::new(tx);

    for it in rx.iter() {
        match it {
            CrustMsg::NewConnection(peer_id) => {
                println!("Routing received new connection with peer {}", peer_id);
                thread::sleep(Duration::from_secs(1));
                service.send(peer_id, vec![243; 10]);
            }
            CrustMsg::NewMessage(peer_id, msg) => {
                println!("Routing received from peer {}: {:?}", peer_id, msg);
                break;
            }
        }
    }
}
