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
//! Reliable p2p network connections in Rust with NAT traversal.
//! One of the most needed libraries for any server-less / decentralised projects

#![forbid(missing_docs, warnings)]
#![deny(bad_style, deprecated, drop_with_repr_extern, improper_ctypes, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints,
        unsafe_code, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http:///dirvine.github.io/crust/crust/")]
#![feature(ip_addr, ip, udp, arc_weak, socket_timeout, duration, negate_unsigned)]

extern crate cbor;
extern crate rand;
extern crate rustc_serialize;
//extern crate sodiumoxide;
extern crate time;
extern crate asynchronous;
extern crate libc;
extern crate utp;
extern crate itertools;
extern crate igd;

#[cfg(test)]
extern crate tempdir;

#[cfg(test)]
mod test {
    use std::env;

    #[test]
    pub fn check_rust_unit_testing_is_not_parallel() {
        match env::var_os("RUST_TEST_THREADS") {
            Some(val) => assert!(val.into_string().unwrap() == "1"),
            None => panic!("RUST_TEST_THREADS needs to be 1 for the crust unit tests to work"),
        }
    }
}
mod beacon;
mod bootstrap_handler;
mod getifaddrs;
mod tcp_connections;
mod utp_connections;
mod transport;
mod config_utils;
mod utils;

/// Module implementing the `ConnectionManager` which provides an interface to manage peer-to-peer
/// connections.
pub mod connection_manager;

pub use connection_manager::{Event, ConnectionManager};
pub use transport::{Endpoint, Port};
pub use config_utils::write_config_file;
