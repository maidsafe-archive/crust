// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use common::{self, ExternalReachability, NameHash};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Message<UID> {
    Heartbeat,
    BootstrapRequest(UID, NameHash, ExternalReachability),
    BootstrapGranted(UID),
    BootstrapDenied(BootstrapDenyReason),
    EchoAddrReq,
    EchoAddrResp(common::SocketAddr),
    ChooseConnection,
    Connect(UID, NameHash),
    Data(Vec<u8>),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BootstrapDenyReason {
    InvalidNameHash,
    FailedExternalReachability,
    NodeNotWhitelisted,
    ClientNotWhitelisted,
}
