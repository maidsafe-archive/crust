// Copyright 2017 MaidSafe.net limited.
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

use priv_prelude::*;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BootstrapRequest {
    pub uid: Uid,
    pub name_hash: NameHash,
    pub ext_reachability: ExternalReachability
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub connection_id: u64,
    pub peer_uid: Uid,
    pub name_hash: NameHash,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HandshakeMessage {
    BootstrapRequest(BootstrapRequest),
    BootstrapGranted(Uid),
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
