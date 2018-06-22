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

/// The result of a `Service::prepare_contact_info` call.
#[derive(Debug)]
pub struct ConnectionInfoResult {
    /// The token that was passed to `prepare_connection_info`.
    pub result_token: u32,
    /// The new contact info, if successful.
    pub result: Result<PubConnectionInfo, CrustError>,
}

/// Enum representing different events that will be sent over the asynchronous channel to the user
/// of this module.
#[derive(Debug)]
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum Event<UID> {
    /// Invoked when a bootstrap peer connects to us
    BootstrapAccept(UID, CrustUser),
    /// Invoked when we bootstrap to a new peer.
    BootstrapConnect(UID, PaAddr),
    /// Invoked when we failed to connect to all bootstrap contacts.
    BootstrapFailed,
    /// Invoked when we are ready to listen for incomming connection. Contains
    /// the listening address.
    ListenerStarted(PaAddr),
    /// Invoked when listener failed to start.
    ListenerFailed,
    /// Invoked as a result to the call of `Service::prepare_contact_info`.
    ConnectionInfoPrepared(ConnectionInfoResult),
    /// Invoked when connection to a new peer has been established.
    ConnectSuccess(UID),
    /// Invoked when connection to a new peer has failed.
    ConnectFailure(UID),
    /// Invoked when a peer disconnects or can no longer be contacted.
    LostPeer(UID),
    /// Invoked when a new message is received. Passes the message.
    NewMessage(UID, CrustUser, Vec<u8>),
    /// Invoked when trying to sending a too large data.
    WriteMsgSizeProhibitive(UID, Vec<u8>),
}
