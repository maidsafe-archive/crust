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

pub use self::core::{Core, CoreMessage, CoreTimer, EventLoop, spawn_event_loop};
pub use self::error::CommonError;
pub use self::message::{BootstrapDenyReason, Message};
pub use self::socket::Socket;
pub use self::state::State;
use rust_sodium::crypto::hash::sha256;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::fmt;
use std::hash::Hash;
use std::net::SocketAddr;

pub type NameHash = [u8; sha256::DIGESTBYTES];
/// Priority of a message to be sent by Crust. A lower value means a higher priority, so Priority 0
/// is the highest one. Low-priority messages will be preempted if need be to allow higher priority
/// messages through. Messages with a value `>= MSG_DROP_PRIORITY` will even be dropped, if
/// bandwidth is insufficient.
pub type Priority = u8;
pub type Result<T> = ::std::result::Result<T, CommonError>;

pub const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;
/// Minimum priority for droppable messages. Messages with lower values will never be dropped.
pub const MSG_DROP_PRIORITY: u8 = 2;

/// Specify crust user. Behaviour (for example in bootstrap phase) will be different for different
/// variants. Node will request the Bootstrapee to connect back to this crust failing which it
/// would mean it's not reachable from outside and hence should be rejected bootstrap attempts.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CrustUser {
    /// Crust user is a Node and should not be allowed to bootstrap if it's not reachable from
    /// outside.
    Node,
    /// Crust user is a Client and should be allowed to bootstrap even if it's not reachable from
    /// outside.
    Client,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExternalReachability {
    NotRequired,
    Required { direct_listeners: Vec<SocketAddr> },
}

/// Trait for specifying a unique identifier for a Crust peer
pub trait Uid: 'static + Send + fmt::Debug + Clone + Copy + Eq + PartialEq + Ord + PartialOrd + Hash +
      Serialize + DeserializeOwned {}

pub mod get_if_addrs;
mod core;
mod error;
mod message;
mod socket;
mod state;
