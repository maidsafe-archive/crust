// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::{CrustUser, NameHash};
use safe_crypto::PublicEncryptKey;
use std::collections::HashSet;
use std::net::SocketAddr;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Message<UID> {
    Heartbeat,
    /// Carries a list of our listener addresses in case remote peer wants to check our
    /// external reachability.
    BootstrapRequest(
        UID,
        NameHash,
        HashSet<SocketAddr>,
        CrustUser,
        PublicEncryptKey,
    ),
    BootstrapGranted(UID),
    BootstrapDenied(BootstrapDenyReason),
    EchoAddrReq(PublicEncryptKey),
    EchoAddrResp(SocketAddr),
    ChooseConnection,
    /// First connect handshake message which goes both ways: peer that initiates connection
    /// sends this message to remote peer, which then responds with the same message, but its own
    /// information.
    /// When `Connect` is used as response message address list is ignored and can be empty. When
    /// it is a request message, it should contain all the addresses we are listening on. Those
    /// addresses will be used for external reachability test.
    // TODO(povilas): consider splitting Connect into ConnectRequest and ConnectResponse
    Connect(UID, NameHash, HashSet<SocketAddr>, PublicEncryptKey),
    Data(Vec<u8>),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BootstrapDenyReason {
    InvalidNameHash,
    FailedExternalReachability,
    NodeNotWhitelisted,
    ClientNotWhitelisted,
}
