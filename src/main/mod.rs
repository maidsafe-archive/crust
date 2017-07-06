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

pub use self::active_connection::{ActiveConnection, INACTIVITY_TIMEOUT_MS};
pub use self::bootstrap::Bootstrap;
pub use self::config_handler::Config;
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
