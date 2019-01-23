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
pub use self::state::State;
use safe_crypto::PublicEncryptKey;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

pub const HASH_SIZE: usize = 32;
pub type NameHash = [u8; HASH_SIZE];
pub type Result<T> = ::std::result::Result<T, CommonError>;

/// Specify crust user. Behaviour (for example in bootstrap phase) will be different for different
/// variants. Node will request the Bootstrapee to connect back to this crust failing which it
/// would mean it's not reachable from outside and hence should be rejected bootstrap attempts.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CrustUser {
    /// Crust user is a Node and should not be allowed to bootstrap if it's not reachable from
    /// outside.
    Node,
    /// Crust user is a Client and should be allowed to bootstrap even if it's not reachable from
    /// outside.
    Client,
}

/// Corresponds to `CrustUser` roles and additionally include public endpoints to test for
/// external reachability.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BootstrapperRole {
    /// `Node` peers are usually requested to be externally reachable, hence include their
    /// public endpoints.
    Node(HashSet<SocketAddr>),
    /// `Client` peers don't include any addresses, because they are never tested for external
    /// reachability.
    Client,
}

impl From<&BootstrapperRole> for CrustUser {
    fn from(role: &BootstrapperRole) -> CrustUser {
        match role {
            BootstrapperRole::Node(_) => CrustUser::Node,
            BootstrapperRole::Client => CrustUser::Client,
        }
    }
}

/// Information necessary to connect to peer.
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer public address.
    pub addr: SocketAddr,
    /// Peer public key.
    pub pub_key: PublicEncryptKey,
}

impl PeerInfo {
    /// Constructs peer info.
    pub fn new(addr: SocketAddr, pub_key: PublicEncryptKey) -> Self {
        Self { addr, pub_key }
    }
}

/// A convevience method to build IPv4 address with a port number.
pub fn ipv4_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
}

mod core;
mod error;
mod message;
mod state;
