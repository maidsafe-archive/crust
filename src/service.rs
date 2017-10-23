use futures::sync::mpsc::UnboundedReceiver;
use priv_prelude::*;

use net::{self, Acceptor, Listener, BootstrapAcceptor, ServiceDiscovery};
use net::nat::{self, mapping_context};

pub const SERVICE_DISCOVERY_DEFAULT_PORT: u16 = 5484;


/// The main entry point to Crust.
pub struct Service<UID: Uid> {
    handle: Handle,
    config: ConfigFile,
    our_uid: UID,
    mc: MappingContext,
    acceptor: Acceptor<UID>,
}

impl<UID: Uid> Service<UID> {
    /// Create a new `Service` with the default config.
    pub fn new(handle: &Handle, our_uid: UID) -> BoxFuture<Service<UID>, CrustError> {
        let try = || -> Result<_, CrustError> {
            Ok(Service::with_config(handle, ConfigFile::open_default()?, our_uid))
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
        let options = mapping_context::Options {
            force_include_port: config.read().force_acceptor_port_in_ext_ep,
        };
        MappingContext::new(options)
        .map_err(|e| CrustError::NatError(e))
        .map(move |mc| {
            let acceptor = Acceptor::new(&handle, our_uid, config.clone());
            Service {
                handle,
                config,
                our_uid,
                mc,
                acceptor,
            }
        })
        .into_boxed()
    }
    
    /// Get a handle to the service's config file.
    pub fn config(&self) -> ConfigFile {
        self.config.clone()
    }

    /// Bootstrap to the network.
    pub fn bootstrap(
        &mut self,
        blacklist: HashSet<SocketAddr>,
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
            self.config.clone()
        )
    }

    /// Start a bootstrap acceptor. The returned `BootstrapAcceptor` can be used to receive peers
    /// who are bootstrapping to us. It can be dropped again to re-disable accepting bootstrapping
    /// peers.
    pub fn bootstrap_acceptor(&mut self) -> BootstrapAcceptor<UID> {
        self.acceptor.bootstrap_acceptor()
    }

    /// Start listening on a socket. The address/port to listen on is configured through the
    /// configuration file, The returned `Listener` can also be queried for the address. Drop the
    /// `Listener` to stop listening on the address.
    pub fn start_listener(&self) -> BoxFuture<Listener, CrustError> {
        let port = self.config.read().tcp_acceptor_port.unwrap_or(0);
        let addr = SocketAddr::new(ip!("0.0.0.0"), port);
        self.acceptor.listener(&addr, &self.mc)
            .map_err(CrustError::StartListener)
            .into_boxed()
    }

    /// Prepare a connection info. This is the first step to doing a p2p connection to a peer. Both
    /// peers must call `prepare_connection_info`, use the returned `PrivConnectionInfo` to
    /// generate a `PubConnectionInfo`, trade `PubConnectionInfo`s using some out-of-channel, then
    /// call connect simultaneously using each other's `PubConnectionInfo` and their own
    /// `PrivConnectionInfo`.
    pub fn prepare_connection_info(&self) -> BoxFuture<PrivConnectionInfo<UID>, CrustError> {
        let our_uid = self.our_uid;
        let (direct_addrs, _) = self.acceptor.addresses();
        nat::mapped_tcp_socket::<UID>(&self.handle, &self.mc, &addr!("0.0.0.0:0"))
        .map(move |(socket, hole_punch_addrs)| {
            PrivConnectionInfo {
                id: our_uid,
                for_direct: direct_addrs.into_iter().collect(),
                for_hole_punch: hole_punch_addrs.into_iter().collect(),
                hole_punch_socket: Some(socket),
            }
        })
        .map_err(CrustError::PrepareConnectionInfo)
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
        ServiceDiscovery::new(
            &self.handle,
            self.config.clone(),
            current_addrs,
            addrs_rx,
        )
    }

    /// Return the set of all addresses that we are currently listening for incoming connections
    /// on. Also returns a channel that can be used to monitor when this set changes.
    pub fn addresses(&self) -> (HashSet<SocketAddr>, UnboundedReceiver<HashSet<SocketAddr>>) {
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

