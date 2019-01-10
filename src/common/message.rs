// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::{BootstrapperRole, NameHash};
use safe_crypto::PublicEncryptKey;
use std::collections::HashSet;
use std::net::SocketAddr;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Message<UID> {
    Heartbeat,
    /// Carries a list of our listener addresses in case remote peer wants to check our
    /// external reachability.
    BootstrapRequest(UID, NameHash, BootstrapperRole, PublicEncryptKey),
    BootstrapGranted(UID),
    BootstrapDenied(BootstrapDenyReason),
    EchoAddrReq(PublicEncryptKey),
    EchoAddrResp(SocketAddr),
    ChooseConnection,
    /// Send this message to initiate connection with remote peer. This message carries our ID,
    /// network name hash, list of public IP:port pairs and our public key.
    ConnectRequest(UID, NameHash, HashSet<SocketAddr>, PublicEncryptKey),
    /// Response of accepted connection that carries remote peer's ID and network name hash.
    ConnectResponse(UID, NameHash),
    Data(Vec<u8>),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BootstrapDenyReason {
    InvalidNameHash,
    FailedExternalReachability,
    NodeNotWhitelisted,
    ClientNotWhitelisted,
}
