// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! #crust
//! Reliable peer-to-peer network connections in Rust with NAT traversal.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
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
// FIXME: `needless_pass_by_value` and `clone_on_ref_ptr` required to make no intrusive changes
// on code in the master branch
#![cfg_attr(
    feature = "cargo-clippy",
    allow(
        clone_on_ref_ptr,
        decimal_literal_representation,
        needless_pass_by_value,
        too_many_arguments
    )
)]
#![recursion_limit = "128"]

#[macro_use]
extern crate log;
#[cfg_attr(feature = "cargo-clippy", allow(useless_attribute))]
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate unwrap;

extern crate config_file_handler;
extern crate crossbeam;
extern crate get_if_addrs;
extern crate igd;
extern crate maidsafe_utilities;
extern crate mio;
extern crate mio_extras;
extern crate net2;
extern crate rand;
extern crate safe_crypto;
extern crate serde;
extern crate socket_collection;

#[cfg(test)]
extern crate serde_json;
#[cfg(test)]
#[macro_use]
mod tests;

mod common;
mod main;
mod nat;
mod service_discovery;

pub use common::{CrustUser, Uid};
pub use main::{
    read_config_file, Config, ConnectionInfoResult, CrustError, Event, PrivConnectionInfo,
    PubConnectionInfo, Service,
};
pub use socket_collection::Priority;

/// Used to receive events from a `Service`.
pub type CrustEventSender<UID> = ::maidsafe_utilities::event_sender::MaidSafeObserver<Event<UID>>;
/// Crust's result type
pub type Res<T> = Result<T, CrustError>;
