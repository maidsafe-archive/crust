// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use self::active_connection::{ActiveConnection, INACTIVITY_TIMEOUT_MS};
pub use self::bootstrap::Bootstrap;
pub use self::config_handler::{Config, DevConfig};
pub use self::config_refresher::ConfigRefresher;
pub use self::connect::Connect;
pub use self::connection_candidate::ConnectionCandidate;
pub use self::connection_listener::ConnectionListener;
pub use self::error::CrustError;
pub use self::event::Event;
pub use self::service::Service;
pub use self::types::{ConfigWrapper, ConnectionId, ConnectionInfoResult, PrivConnectionInfo,
                      PubConnectionInfo};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub type ConnectionMap<UID> = Arc<Mutex<HashMap<UID, ConnectionId>>>;
pub type CrustConfig = Arc<Mutex<ConfigWrapper>>;

mod active_connection;
mod bootstrap;
mod config_handler;
mod config_refresher;
mod connect;
mod connection_candidate;
mod connection_listener;
mod event;
mod error;
mod service;
mod types;

pub use self::config_handler::read_config_file;
