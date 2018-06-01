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

//! This module is a backwards-compatibility layer which implements the old message-passing-based
//! API on top of the new futures API.

pub use self::connection_map::ConnectionMap;
pub use self::event::{ConnectionInfoResult, Event};
pub use self::event_loop::EventLoop;
pub use self::service::Service;
use maidsafe_utilities;

mod connection_map;
mod event;
mod event_loop;
mod service;

/// Used to receive events from a `Service`.
pub type CrustEventSender<UID> = maidsafe_utilities::event_sender::MaidSafeObserver<Event<UID>>;
