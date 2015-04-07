//! #crust
//! Reliable p2p network connections in Rust with NAT traversal.
//! One of the most needed libraries for any server-less / decentralised projects

#![allow(unused_variables)]

#![feature(alloc)]

extern crate rustc_serialize;
extern crate cbor;

pub mod tcp_connections;
pub mod connection_manager;

#[test]
fn it_works() {
}
