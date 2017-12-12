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

use futures::sync::mpsc::UnboundedReceiver;
use net::listener::{Listener, Listeners};
use net::peer::BootstrapAcceptor;
use net::peer::connect::Demux;

use priv_prelude::*;

/// Manages a set of listening sockets and performs functions which involve accepting connections
/// on these sockets (eg. connecting to a peer, which may actually mean accepting their incoming
/// connection).
// Internally this just uses a `Listeners` to accept the connections, and plugs it into a `Demux`
// to route the incoming connections to the other parts of crust where they're needed.
pub struct Acceptor<UID: Uid> {
    listeners: Listeners,
    demux: Demux<UID>,
    handle: Handle,
    our_uid: UID,
    config: ConfigFile,
}

impl<UID: Uid> Acceptor<UID> {
    /// Create a new acceptor.
    pub fn new(handle: &Handle, our_uid: UID, config: ConfigFile) -> Acceptor<UID> {
        let (listeners, socket_incoming) = Listeners::new(handle);
        let demux = Demux::new(handle, socket_incoming);
        let handle = handle.clone();
        Acceptor {
            listeners,
            demux,
            handle,
            config,
            our_uid,
        }
    }

    /// Get the set of addresses that we're currently contactable on. This includes all known
    /// addressess including mapped addresses on the other side of a NAT. The returned receiver can
    /// be used to be notified when the set of known addresses changes.
    pub fn addresses(&self) -> (HashSet<PaAddr>, UnboundedReceiver<HashSet<PaAddr>>) {
        self.listeners.addresses()
    }

    /// Add a listener to the set of listeners and return a handle to it.
    pub fn listener(&self, listen_addr: &PaAddr) -> IoFuture<Listener> {
        self.listeners.listener::<UID>(listen_addr)
    }

    /// Create a new `BootstrapAcceptor` for accepting bootstrapping peers.
    pub fn bootstrap_acceptor(&self) -> BootstrapAcceptor<UID> {
        self.demux.bootstrap_acceptor(
            &self.handle,
            self.config.clone(),
            self.our_uid,
        )
    }

    /// Perform a rendezvous connect to another peer.
    pub fn connect(
        &self,
        name_hash: NameHash,
        our_info: PrivConnectionInfo<UID>,
        their_info: PubConnectionInfo<UID>,
    ) -> BoxFuture<Peer<UID>, ConnectError> {
        self.demux.connect(
            &self.handle,
            name_hash,
            our_info,
            their_info,
            //self.config.clone(),
        )
    }
}
