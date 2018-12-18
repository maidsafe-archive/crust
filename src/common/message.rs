// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use common::{self, ExternalReachability, NameHash};
use safe_crypto::PublicEncryptKey;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Message<UID> {
    Heartbeat,
    BootstrapRequest(UID, NameHash, ExternalReachability, PublicEncryptKey),
    BootstrapGranted(UID),
    BootstrapDenied(BootstrapDenyReason),
    EchoAddrReq(PublicEncryptKey),
    EchoAddrResp(common::SocketAddr),
    ChooseConnection,
    Connect(UID, NameHash, PublicEncryptKey),
    Data(Vec<u8>),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BootstrapDenyReason {
    InvalidNameHash,
    FailedExternalReachability,
    NodeNotWhitelisted,
    ClientNotWhitelisted,
}
