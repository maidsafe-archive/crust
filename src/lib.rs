// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

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
#[cfg(test)]
#[macro_use]
extern crate rand_derive;
extern crate env_logger;
extern crate tiny_keccak;
extern crate notify;
#[macro_use]
extern crate maplit;
extern crate igd;
#[cfg(test)]
#[macro_use]
extern crate hamcrest;
extern crate p2p;

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

pub use common::CrustUser;
pub use config::ConfigFile;
pub use error::CrustError;
pub use net::{Peer, PrivConnectionInfo, PubConnectionInfo};
pub use net::Uid;
pub use service::Service;
