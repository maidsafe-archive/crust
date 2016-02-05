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

use endpoint::Endpoint;
use connection::{RaiiTcpAcceptor, Connection};
use std::net::UdpSocket;
use socket_addr::SocketAddr;
use sodiumoxide::crypto::sign::PublicKey;
use std::io;
use static_contact_info::StaticContactInfo;
use connection_info::ConnectionInfoResult;

// This is necessary to gracefully exit the threads. In current design, there is no control over
// the network reader threads - they infinitely block. So this workaround will use the writer
// thread to shutdown the stream so that the reader thread exits. Better design should be sought in
// the future.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteEvent {
    Write(Vec<u8>),
    Shutdown,
}

/// Enum representing different events that will be sent over the asynchronous channel to the user
/// of this module.
#[derive(Debug)]
pub enum Event {
    /// Invoked when a new message is received.  Passes the peer's public key and the message.
    NewMessage(PublicKey, Vec<u8>),
    /// Invoked when we get a new bootstrap connection.
    /// Passes the new connection and the peer's public key.
    NewBootstrapConnection {
        /// The connection object.
        connection: Connection,
        /// The peer's public key.
        their_pub_key: PublicKey,
    },
    /// Invoked when the new rendezvous connection request finishes.
    /// Passes the new connection and the peer's public key.
    NewConnection {
        /// The connection object.
        connection: io::Result<Connection>,
        /// The peer's public key.
        their_pub_key: PublicKey,
    },
    /// Invoked when a connection to a peer is lost.  Passes the peer's public key.
    LostConnection(PublicKey),
    /// TODO THIS IS WRONG - Invoked when a new bootstrap connection to a peer is established.
    /// Passes the peer's endpoint.
    BootstrapFinished,
    /// Invoked when a new bootstrap connection to a peer is established.
    /// Passes the peer's endpoint.
    ExternalEndpoints(Vec<Endpoint>),
    /// Invoked as a result to the call of `Service::prepare_contact_info`.
    ConnectionInfoPrepared(ConnectionInfoResult),
}
