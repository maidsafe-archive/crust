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

use transport::Endpoint;

/// Enum representing different events that will be sent over the asynchronous channel to the user
/// of this module.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Event {
    /// Invoked when a new message is received.  Passes the peer's endpoint and the message.
    NewMessage(Endpoint, Vec<u8>),
    /// Invoked when a new connection to a peer is established.  Passes the peer's endpoint.
    NewConnection(Endpoint),
    /// Invoked when a connection to a peer is lost.  Passes the peer's endpoint.
    LostConnection(Endpoint),
    /// Invoked when a new bootstrap connection to a peer is established.  Passes the peer's endpoint.
    NewBootstrapConnection(Endpoint),
}

