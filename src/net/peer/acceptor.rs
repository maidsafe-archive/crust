use futures::sync::mpsc::UnboundedReceiver;
use net::listener::{Listeners, Listener};
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
    pub fn new(
        handle: &Handle,
        our_uid: UID,
        config: ConfigFile,
    ) -> Acceptor<UID> {
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
    pub fn addresses(&self) -> (HashSet<SocketAddr>, UnboundedReceiver<HashSet<SocketAddr>>) {
        self.listeners.addresses()
    }

    /// Add a listener to the set of listeners and return a handle to it.
    pub fn listener(
        &self,
        listen_addr: &SocketAddr,
        mc: &MappingContext,
    ) -> IoFuture<Listener> {
        self.listeners.listener::<UID>(listen_addr, mc)
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
            self.config.clone(),
        )
    }
}

