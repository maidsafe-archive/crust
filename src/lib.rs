// Copyright 2015 MaidSafe.net limited.
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

//! #crust
//! Reliable peer-to-peer network connections in Rust with NAT traversal.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/crust/")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

// Uncomment to use Clippy
// #![feature(plugin)]
// #![plugin(clippy)]

extern crate cbor;
extern crate igd;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate net2;
extern crate rand;
extern crate rustc_serialize;
extern crate time;
extern crate utp;
extern crate crossbeam;
#[macro_use]
extern crate maidsafe_utilities;
extern crate ip;
extern crate get_if_addrs;
extern crate config_file_handler;

/// Module implementing the `Service` which provides an interface to manage peer-to-peer
/// connections.
pub mod service;

/// Crust Observers will be informed of crust events on this
pub type CrustEventSender = ::maidsafe_utilities::event_sender::MaidSafeObserver<Event>;
pub use config_handler::write_config_file;
pub use service::Service;
pub use event::{ContactInfoResult, Event, OurContactInfo, TheirContactInfo};
pub use endpoint::{Endpoint, Protocol};
pub use connection::Connection;
pub use socket_addr::SocketAddr;
pub use hole_punching::HolePunchServer;

#[cfg(test)]
mod test {
    #[test]
    pub fn check_rust_unit_testing_is_not_parallel() {
        match ::std::env::var_os("RUST_TEST_THREADS") {
            Some(val) => assert!(val.into_string().unwrap() == "1"),
            None => panic!("RUST_TEST_THREADS needs to be 1 for the crust unit tests to work"),
        }
    }
}
mod sequence_number;
mod connection;
mod beacon;
mod endpoint;
mod bootstrap_handler;
mod config_handler;
mod util;
mod tcp_connections;
mod transport;
mod utp_connections;
mod utp_wrapper;
mod event;
mod map_external_port;
mod hole_punching;
mod periodic_sender;
mod socket_utils;
mod socket_addr;
mod ip_info;
mod acceptor;
mod connection_map;

