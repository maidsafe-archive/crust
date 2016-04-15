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
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]
#![cfg_attr(feature="clippy", allow(use_debug))]

extern crate itertools;
#[macro_use]
extern crate log;
extern crate net2;
extern crate rand;
extern crate rustc_serialize;
extern crate utp;
#[macro_use]
extern crate maidsafe_utilities;
extern crate socket_addr;
extern crate get_if_addrs;
extern crate sodiumoxide;
extern crate config_file_handler;
extern crate service_discovery;
extern crate nat_traversal;
#[cfg(test)]
extern crate void;
extern crate crossbeam;

#[allow(unused_extern_crates)] // Needed because the crate is only used for macros
#[macro_use]
extern crate quick_error;

/// Crust Observers will be informed of crust events on this
pub type CrustEventSender = ::maidsafe_utilities::event_sender::MaidSafeObserver<Event>;
pub use config_handler::{read_config_file, write_config_file};
pub use service::{ConnectionInfoResult, OurConnectionInfo, Service, TheirConnectionInfo,
                  DEFAULT_BEACON_PORT};
pub use event::Event;
pub use endpoint::{Endpoint, Protocol};
pub use socket_addr::SocketAddr;
pub use static_contact_info::StaticContactInfo;
pub use error::Error;
pub use peer_id::PeerId;

mod error;
mod service;
mod bootstrap;
mod connection;
mod listener_message;
mod endpoint;
mod bootstrap_handler;
mod config_handler;
mod util;
mod tcp_connections;
mod utp_connections;
mod sender_receiver;
mod static_contact_info;
mod utp_wrapper;
mod event;
mod socket_utils;
mod ip_info;
mod peer_id;
mod udp_listener;
