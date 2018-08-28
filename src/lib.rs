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

//! #crust
//! Reliable peer-to-peer network connections in Rust with NAT traversal.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    html_root_url = "https://docs.rs/crust"
)]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

extern crate bytes;
extern crate config_file_handler;
#[cfg(test)]
extern crate env_logger;
extern crate future_utils;
extern crate futures;
extern crate get_if_addrs;
#[cfg(test)]
#[macro_use]
extern crate hamcrest;
#[macro_use]
extern crate log;
extern crate lru_time_cache;
extern crate maidsafe_utilities;
#[cfg(test)]
#[macro_use]
extern crate maplit;
extern crate net2;
#[macro_use]
extern crate net_literals;
extern crate notify;
extern crate p2p;
#[macro_use]
extern crate quick_error;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tiny_keccak;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_utp;
#[macro_use]
extern crate unwrap;
extern crate safe_crypto;
extern crate url;
extern crate void;

#[cfg(test)]
#[cfg(target_os = "linux")]
#[cfg(feature = "netsim")]
extern crate netsim;

mod error;
#[macro_use]
mod util;
#[macro_use]
mod net;
mod common;
pub mod compat;
pub mod config;
mod service;

mod priv_prelude;

#[cfg(test)]
mod tests;

pub use common::CrustUser;
pub use config::ConfigFile;
pub use error::CrustError;
pub use net::{Listener, PaAddr, Peer, PeerError, PrivConnectionInfo, PubConnectionInfo};
pub use service::Service;

/// Crust maximum message size
pub const MAX_PAYLOAD_SIZE: usize = 8 * 1024 * 1024;
