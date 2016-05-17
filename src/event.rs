// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use peer_id::PeerId;
use service::ConnectionInfoResult;
// use std::io;
// use std::time::Instant;
// use sender_receiver::CrustMsg;

// // This is necessary to gracefully exit the threads. In current design, there is no control over
// // the network reader threads - they infinitely block. So this workaround will use the writer
// // thread to shutdown the stream so that the reader thread exits. Better design should be sought in
// // the future.
// #[derive(Clone, Debug, Eq, PartialEq)]
// pub enum WriteEvent {
//     Write(CrustMsg, Instant, u8),
//     Shutdown,
// }

/// Enum representing different events that will be sent over the asynchronous channel to the user
/// of this module.
#[derive(Debug)]
pub enum Event {
    // /// Invoked when a bootstrap peer connects to us
    // BootstrapAccept(PeerId),
    // /// Invoked when we get a bootstrap connection to a new peer.
    // BootstrapConnect(PeerId),
    // /// Raised once the list of bootstrap contacts is exhausted.
    // BootstrapFinished,
    /// Invoked as a result to the call of `Service::prepare_contact_info`.
    ConnectionInfoPrepared(ConnectionInfoResult),
    /// Invoked when a peer is lost or having read/write error.
    LostPeer(PeerId),
    /// Invoked when a new connection get established.
    NewConnection(PeerId),
    /// Invoked when a new message is received.  Passes the message.
    NewMessage(PeerId, Vec<u8>),
    // /// Invoked when a connection to a new peer is established.
    // NewPeer(io::Result<()>, PeerId),
    /// Invoked when trying to sending a too large data.
    WriteMsgSizeProhibitive(PeerId, Vec<u8>),
}
