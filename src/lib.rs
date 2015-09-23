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

//#![forbid(missing_docs, warnings)]
//#![deny(bad_style, deprecated, drop_with_repr_extern, improper_ctypes, non_shorthand_field_patterns,
//        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
//        raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints,
//        unsafe_code, unused_allocation, unused_attributes,
//        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/crust/")]
#![feature(fnbox, ip_addr, ip)]
#![allow(unused_variables)]

extern crate asynchronous;
extern crate cbor;
extern crate igd;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate libc;
extern crate net2;
extern crate rand;
extern crate rustc_serialize;
extern crate time;
extern crate utp;

/// Module implementing the `Service` which provides an interface to manage peer-to-peer
/// connections.
pub mod service;
/// Defines errors.
pub mod error;
/// Provides a struct and free functions for working with config files.
pub mod file_handler;

pub use config_handler::write_config_file;
pub use service::Service;
pub use event::Event;
pub use error::Error;
pub use file_handler::{FileHandler, current_bin_dir, user_app_dir, system_cache_dir, exe_file_stem,
                       ScopedUserAppDirRemover};
pub use transport::{Endpoint, Port, Protocol};
pub use connection::Connection;
pub use util::ifaddr_if_unspecified;
pub use getifaddrs::getifaddrs;

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
mod beacon;
mod bootstrap_handler;
mod config_handler;
mod util;
mod ip;
mod getifaddrs;
mod connection;
mod tcp_connections;
mod transport;
mod utp_connections;
mod utp_wrapper;
mod state;
mod event;
mod map_external_port;
