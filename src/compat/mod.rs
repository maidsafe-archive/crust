// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! This module is a backwards-compatibility layer which implements the old message-passing-based
//! API on top of the new futures API.

pub use self::event::{ConnectionInfoResult, Event};
pub use self::peer::{CompatPeer, CompatPeerError, Priority};
pub use self::service::Service;
use maidsafe_utilities;

mod connection_map;
mod event;
mod event_loop;
mod peer;
mod service;

/// Used to receive events from a `Service`.
pub type CrustEventSender = maidsafe_utilities::event_sender::MaidSafeObserver<Event>;
