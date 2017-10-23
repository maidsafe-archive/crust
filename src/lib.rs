// Temporarily allow these while doing heavy refactoring
#![allow(dead_code)]
#![allow(unused_imports)]

extern crate maidsafe_utilities;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate config_file_handler;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate unwrap;
extern crate tokio_core;
extern crate tokio_io;
extern crate futures;
extern crate future_utils;
extern crate net2;
#[macro_use]
extern crate net_literals;
extern crate get_if_addrs;
#[macro_use]
extern crate log;
extern crate void;
extern crate bytes;
extern crate rand;
#[macro_use]
extern crate rand_derive;
extern crate env_logger;
extern crate tiny_keccak;
extern crate notify;
#[macro_use]
extern crate maplit;
extern crate igd;

pub use net::MAX_PAYLOAD_SIZE;

mod error;
mod config;
mod common;
pub mod compat;
mod service;
mod util;
mod net;

mod priv_prelude;

#[cfg(test)]
mod tests;

pub use config::ConfigFile;
pub use service::Service;
pub use error::CrustError;
pub use common::CrustUser;
pub use net::{PrivConnectionInfo, PubConnectionInfo};
pub use net::Uid;

