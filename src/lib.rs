// Copyright 2016 MaidSafe.net limited.
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

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "https://maidsafe.net/img/favicon.ico",
       html_root_url = "https://docs.rs/crust")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="cargo-clippy", allow(too_many_arguments))]
// TODO FIXME Remove this soon
#![allow(deprecated)]

#[macro_use]
extern crate log;
#[cfg_attr(feature="cargo-clippy", allow(useless_attribute))]
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate unwrap;

extern crate byteorder;
extern crate c_linked_list;
extern crate config_file_handler;
extern crate crossbeam;
extern crate igd;
extern crate libc;
extern crate maidsafe_utilities;
extern crate mio;
extern crate net2;
extern crate rand;
extern crate rust_sodium;
extern crate serde;

#[cfg(windows)]
extern crate winapi;

#[cfg(test)]
extern crate serde_json;
#[cfg(test)]
#[macro_use]
mod tests;

mod main;
mod common;
mod service_discovery;
mod nat;

pub use common::{CrustUser, MSG_DROP_PRIORITY, Priority, Uid};
pub use main::{Config, ConnectionInfoResult, CrustError, Event, PrivConnectionInfo,
               PubConnectionInfo, Service};

/// Used to receive events from a `Service`.
pub type CrustEventSender<UID> = ::maidsafe_utilities::event_sender::MaidSafeObserver<Event<UID>>;
/// Crust's result type
pub type Res<T> = Result<T, CrustError>;
