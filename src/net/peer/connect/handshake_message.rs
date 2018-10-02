// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use priv_prelude::*;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BootstrapRequest {
    pub name_hash: NameHash,
    pub ext_reachability: ExternalReachability,
    pub client_uid: PublicEncryptKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub connection_id: u64,
    pub client_uid: PublicEncryptKey,
    pub name_hash: NameHash,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HandshakeMessage {
    BootstrapRequest(BootstrapRequest),
    BootstrapGranted,
    BootstrapDenied(BootstrapDenyReason),
    ChooseConnection,
    Connect(ConnectRequest),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BootstrapDenyReason {
    InvalidNameHash,
    FailedExternalReachability,
    NodeNotWhitelisted,
    ClientNotWhitelisted,
}
