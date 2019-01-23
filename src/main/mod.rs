// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub use self::active_connection::{ActiveConnection, INACTIVITY_TIMEOUT_MS};
pub use self::bootstrap::Bootstrap;
#[cfg(test)]
pub use self::bootstrap::Cache as BootstrapCache;
pub use self::config_handler::Config;
pub use self::config_refresher::ConfigRefresher;
pub use self::connect::Connect;
pub use self::connection_candidate::ConnectionCandidate;
pub use self::connection_listener::ConnectionListener;
pub use self::error::CrustError;
pub use self::event::Event;
pub use self::service::Service;
pub use self::types::{
    ConfigWrapper, ConnectionId, ConnectionInfoResult, CrustData, EventLoop, EventLoopCore,
    GetGlobalListenerAddrs, PrivConnectionInfo, PubConnectionInfo,
};

mod active_connection;
mod bootstrap;
mod config_handler;
mod config_refresher;
mod connect;
mod connection_candidate;
mod connection_listener;
mod error;
mod event;
mod service;
mod types;

pub use self::config_handler::read_config_file;

use safe_crypto::{PublicEncryptKey, PublicSignKey};

/// Used to identify unique peers.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct PeerId {
    /// Public signing key is not used by Crust itself, but it is passed to Crust users when
    /// new peers are found.
    pub pub_sign_key: PublicSignKey,
    /// Crust uses this field to actually identify different peers.
    pub pub_enc_key: PublicEncryptKey,
}
