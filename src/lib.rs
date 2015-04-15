//! #crust
//! Reliable p2p network connections in Rust with NAT traversal.
//! One of the most needed libraries for any server-less / decentralised projects

#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http:///dirvine.github.io/crust/crust/")]
#![allow(unused_variables)]

#![feature(alloc, udp)]

extern crate rustc_serialize;
extern crate cbor;

mod tcp_connections;
pub mod connection_manager;
mod beacon;

pub use connection_manager::{Event, ConnectionManager};

#[test]
fn it_works() {
}
