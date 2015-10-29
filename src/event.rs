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
use connection::Connection;
use std::net::{UdpSocket, SocketAddr};
use std::collections::HashSet;
use std::io;

#[derive(Debug)]
pub struct MappedUdpSocket {
    pub result_token: u32,
    // Using HashSet because SocketAddr is not Ord.
    pub result: io::Result<(UdpSocket, HashSet<SocketAddr>)>,
}

#[derive(Debug)]
pub struct HolePunchResult {
    pub result_token: u32,
    pub udp_socket:   UdpSocket,
    pub peer_addr:    io::Result<SocketAddr>,
}

/// Enum representing different events that will be sent over the asynchronous channel to the user
/// of this module.
#[derive(Debug)]
pub enum Event {
    /// Invoked when a new message is received.  Passes the peer's endpoint and the message.
    NewMessage(Connection, Vec<u8>),
    /// Invoked when a new connection to a peer is established. Passes the peer's endpoint.
    OnConnect(Connection, u32 /* token */),
    /// Invoked when a new rendezvous connection to a peer is established. Passes the peer's endpoint.
    OnRendezvousConnect(Connection, u32 /* token */),
    /// Invoked when a new connection is accepted. Passes the peer's endpoint.
    OnAccept(Connection),
    /// Invoked when a connection to a peer is lost.  Passes the peer's endpoint.
    LostConnection(Connection),
    /// Invoked when a new bootstrap connection to a peer is established.  Passes the peer's endpoint.
    BootstrapFinished,
    /// Invoked when a new bootstrap connection to a peer is established.  Passes the peer's endpoint.
    ExternalEndpoints(Vec<Endpoint>),
    /// Invoked as a result of the call to Service::get_mapped_udp_socket.
    OnUdpSocketMapped(MappedUdpSocket),
    /// Invoked as a result of the call to Service::udp_punch_hole.
    OnHolePunched(HolePunchResult),
}

