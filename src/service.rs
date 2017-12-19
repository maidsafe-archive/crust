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


use future_utils::bi_channel;
use futures::sync::mpsc::UnboundedReceiver;
use net::{self, Acceptor, BootstrapAcceptor, Listener, ServiceDiscovery};
use p2p::P2p;
use priv_prelude::*;

pub const SERVICE_DISCOVERY_DEFAULT_PORT: u16 = 5484;


/// The main entry point to Crust.
///
/// Use `Service` to accept incoming connections and to connect to remote peers.
/// There are two methods to initialize connections: `connect()` and `bootstrap()`.
/// Call `start_listener()` to accept connections.
///
/// By default no one can bootstrap off the listener, meaning no one can
/// connect to you with `bootstrap()`. To enable bootstrapping call
/// `bootstrap_acceptor()`.
///
/// `Service` provides futures based API compatible with [Tokio](https://tokio.rs/) event loop.
///
/// Once you are connected, use [Peer](struct.Peer.html) to exchange data.
pub struct Service<UID: Uid> {
    handle: Handle,
    config: ConfigFile,
    our_uid: UID,
    acceptor: Acceptor<UID>,
    p2p: P2p,
}

impl<UID: Uid> Service<UID> {
    /// Create a new `Service` with the default config.
    pub fn new(handle: &Handle, our_uid: UID) -> BoxFuture<Service<UID>, CrustError> {
        let try = || -> Result<_, CrustError> {
            Ok(Service::with_config(
                handle,
                ConfigFile::open_default()?,
                our_uid,
            ))
        };
        future::result(try()).flatten().into_boxed()
    }

    /// Create a new `Service` with the given configuration.
    pub fn with_config(
        handle: &Handle,
        config: ConfigFile,
        our_uid: UID,
    ) -> BoxFuture<Service<UID>, CrustError> {
        let handle = handle.clone();

        let p2p = P2p::default();
        let force_use_local_port = config.read().force_acceptor_port_in_ext_ep;
        p2p.set_force_use_local_port(force_use_local_port);

        let acceptor = Acceptor::new(&handle, our_uid, config.clone(), p2p.clone());
        future::ok(Service {
            handle,
            config,
            our_uid,
            acceptor,
            p2p,
        }).into_boxed()
    }

    /// Get a handle to the service's config file.
    pub fn config(&self) -> ConfigFile {
        self.config.clone()
    }

    /// Bootstrap to the network.
    ///
    /// Bootstrap concept is interchangeable with "connect". Except in context
    /// of Crust bootstrapping is more powerful then a simple `connect()`.
    /// `bootstrap()` will try to connect to all peers that are specified
    /// in config (`hard_coded_contacts`) or were cached.
    ///
    /// Returns a future that resolves to the first connected peer.
    pub fn bootstrap(
        &mut self,
        blacklist: HashSet<PaAddr>,
        use_service_discovery: bool,
        crust_user: CrustUser,
    ) -> BoxFuture<Peer<UID>, BootstrapError> {
        let (current_addrs, _) = self.acceptor.addresses();
        let ext_reachability = match crust_user {
            CrustUser::Node => {
                ExternalReachability::Required {
                    direct_listeners: current_addrs.into_iter().collect(),
                }
            }
            CrustUser::Client => ExternalReachability::NotRequired,
        };
        net::bootstrap(
            &self.handle,
            self.our_uid,
            self.config.network_name_hash(),
            ext_reachability,
            blacklist,
            use_service_discovery,
            &self.config,
        )
    }

    /// Start a bootstrap acceptor. The returned `BootstrapAcceptor` can be used to receive peers
    /// who are bootstrapping to us. It can be dropped again to re-disable accepting bootstrapping
    /// peers.
    pub fn bootstrap_acceptor(&mut self) -> BootstrapAcceptor<UID> {
        self.acceptor.bootstrap_acceptor()
    }

    /// Start listening for incoming connections. The address/port to listen on is configured
    /// through the configuration file. The returned `Listener`s can be queried for their
    /// address, drop a `Listener` to stop listening on its address. The stream will end once all
    /// configured listeners have been returned.
    pub fn start_listening(&self) -> BoxStream<Listener, CrustError> {
        let addrs = &self.config.read().listen_addresses;
        let mut futures = Vec::new();
        for addr in addrs {
            futures.push({
                self.acceptor.listener(addr).map_err(
                    CrustError::StartListener,
                )
            });
        }
        stream::futures_unordered(futures).into_boxed()
    }

    /// Prepare a connection info. This is the first step to doing a p2p connection to a peer. Both
    /// peers must call `prepare_connection_info`, use the returned `PrivConnectionInfo` to
    /// generate a `PubConnectionInfo`, trade `PubConnectionInfo`s using some out-of-channel, then
    /// call connect simultaneously using each other's `PubConnectionInfo` and their own
    /// `PrivConnectionInfo`.
    pub fn prepare_connection_info(&self) -> BoxFuture<PrivConnectionInfo<UID>, CrustError> {
        let our_uid = self.our_uid;
        let (direct_addrs, _) = self.acceptor.addresses();

        let (ch1, ch2) = bi_channel::unbounded();
        let conn_rx = net::peer::start_rendezvous_connect(&self.handle, ch2, &self.p2p);

        ch1.into_future()
            .and_then(move |(conn_info_opt, chann)| {
                let p2p_conn_info = conn_info_opt.and_then(|raw_info| {
                    Some(P2pConnectionInfo {
                        our_info: raw_info,
                        rendezvous_channel: chann,
                        connection_rx: conn_rx,
                    })
                });
                Ok(PrivConnectionInfo {
                    id: our_uid,
                    for_direct: direct_addrs.into_iter().collect(),
                    p2p_conn_info: p2p_conn_info,
                })
            })
            .map_err(|(e, _stream)| e)
            .infallible()
            .into_boxed()
    }

    /// Perform a p2p connection to a peer. You must generate connection info first using
    /// `prepare_connection_info`.
    pub fn connect(
        &self,
        our_info: PrivConnectionInfo<UID>,
        their_info: PubConnectionInfo<UID>,
    ) -> BoxFuture<Peer<UID>, ConnectError> {
        self.acceptor.connect(
            self.config.network_name_hash(),
            our_info,
            their_info,
        )
    }

    /// The returned `ServiceDiscovery` advertises the existence of this peer to any other peers on
    /// the local network (via udp broadcast).
    pub fn start_service_discovery(&self) -> io::Result<ServiceDiscovery> {
        let (current_addrs, addrs_rx) = self.acceptor.addresses();
        ServiceDiscovery::new(&self.handle, self.config.clone(), current_addrs, addrs_rx)
    }

    /// Return the set of all addresses that we are currently listening for incoming connections
    /// on. Also returns a channel that can be used to monitor when this set changes.
    pub fn addresses(&self) -> (HashSet<PaAddr>, UnboundedReceiver<HashSet<PaAddr>>) {
        self.acceptor.addresses()
    }

    /// Get our ID.
    pub fn id(&self) -> UID {
        self.our_uid
    }

    /// Get the tokio `Handle` that this service is using.
    pub fn handle(&self) -> &Handle {
        &self.handle
    }
}
