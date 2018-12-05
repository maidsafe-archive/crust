// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub use self::core::{spawn_event_loop, Core, CoreMessage, CoreTimer, EventLoop};
pub use self::error::CommonError;
pub use self::message::{BootstrapDenyReason, Message};
pub use self::mio_ext::MioReadyExt;
pub use self::socket::Socket;
pub use self::state::State;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::fmt;
use std::hash::Hash;
use std::net::SocketAddr;

pub const HASH_SIZE: usize = 32;
pub type NameHash = [u8; HASH_SIZE];
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
pub trait Uid:
    'static
    + Send
    + fmt::Debug
    + Clone
    + Copy
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Hash
    + Serialize
    + DeserializeOwned
{
}

mod core;
mod error;
mod message;
mod mio_ext;
mod socket;
mod state;
