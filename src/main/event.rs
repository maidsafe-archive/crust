// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::ConnectionInfoResult;

use crate::common::CrustUser;
use crate::PeerId;
use std::net::SocketAddr;

/// Enum representing different events that will be sent over the asynchronous channel to the user
/// of this module.
#[derive(Debug)]
pub enum Event {
    /// Invoked when a bootstrap peer connects to us
    BootstrapAccept(PeerId, CrustUser),
    /// Invoked when we bootstrap to a new peer.
    BootstrapConnect(PeerId, SocketAddr),
    /// Invoked when we failed to connect to all bootstrap contacts.
    BootstrapFailed,
    /// Invoked when we are ready to listen for incomming connection. Contains
    /// the listening port.
    ListenerStarted(u16),
    /// Invoked when listener failed to start.
    ListenerFailed,
    /// Invoked as a result to the call of `Service::prepare_contact_info`.
    ConnectionInfoPrepared(ConnectionInfoResult),
    /// Invoked when connection to a new peer has been established.
    ConnectSuccess(PeerId),
    /// Invoked when connection to a new peer has failed.
    ConnectFailure(PeerId),
    /// Invoked when a peer disconnects or can no longer be contacted.
    LostPeer(PeerId),
    /// Invoked when a new message is received. Passes the message.
    NewMessage(PeerId, CrustUser, Vec<u8>),
    /// Invoked when trying to sending a too large data.
    WriteMsgSizeProhibitive(PeerId, Vec<u8>),
}
