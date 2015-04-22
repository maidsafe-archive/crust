//! #crust
//! Reliable p2p network connections in Rust with NAT traversal.
//! One of the most needed libraries for any server-less / decentralised projects

#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http:///dirvine.github.io/crust/crust/")]
#![allow(unused_variables)]

#![feature(ip_addr, alloc, udp)]

extern crate rustc_serialize;
extern crate cbor;
extern crate time;
extern crate sodiumoxide;

mod tcp_connections;
mod transport;
pub mod connection_manager;
mod beacon;
mod bootstrap;

pub use connection_manager::{Event, ConnectionManager};
pub use transport::{Endpoint, Port};

#[test]
fn it_works() {
}
