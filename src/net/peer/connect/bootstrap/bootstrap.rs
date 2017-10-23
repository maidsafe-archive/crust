use net::service_discovery;
use log::LogLevel;
use config_file_handler;

use priv_prelude::*;
use net::peer::connect::bootstrap::{TryPeerError, ConnectHandshakeError};
use net::peer::connect::bootstrap::try_peer::try_peer;
use net::peer::connect::bootstrap::cache::Cache;
use service;

const BOOTSTRAP_TIMEOUT_SEC: u64 = 10;

quick_error! {
    /// Error returned when bootstrapping fails.
    #[derive(Debug)]
    pub enum BootstrapError {
        ReadCache(e: config_file_handler::Error)  {
            description("Error reading bootstrap cache")
            display("Error reading bootstrap cache: {}", e)
            cause(e)
            from()
        }
        ServiceDiscovery(e: io::Error) {
            description("IO error using service discovery")
            display("IO error using service discovery: {}", e)
            cause(e)
        }
        AllPeersFailed(e: HashMap<SocketAddr, TryPeerError>) {
            description("Failed to connect to any bootstrap peer")
            display("Failed to connect to any bootstrap peer, all {} attempts failed. Errors: {:?}", e.len(), e)
        }
        TimerIo(e: io::Error) {
            description("io error creating tokio timer")
            display("io error creating tokio timer: {}", e)
            cause(e)
        }
    }
}

/// Try to bootstrap to the network.
///
/// On success, returns the peer that we've bootstrapped to.
pub fn bootstrap<UID: Uid>(
    handle: &Handle,
    our_uid: UID,
    name_hash: NameHash,
    ext_reachability: ExternalReachability,
    blacklist: HashSet<SocketAddr>,
    use_service_discovery: bool,
    config: ConfigFile,
) -> BoxFuture<Peer<UID>, BootstrapError> {
    let handle = handle.clone();
    let try = || -> Result<_, BootstrapError> {
        let mut peers = Vec::new();
        let mut cache = Cache::new(config.read().bootstrap_cache_name.as_ref().map(|p| p.as_ref()))?;
        peers.extend(cache.read_file());
        peers.extend(config.read().hard_coded_contacts.iter().cloned());

        let sd_peers = if use_service_discovery {
            let sd_port = config.read().service_discovery_port
                .unwrap_or(service::SERVICE_DISCOVERY_DEFAULT_PORT);
            service_discovery::discover::<Vec<SocketAddr>>(&handle, sd_port)
            .map_err(BootstrapError::ServiceDiscovery)?
            .infallible::<(SocketAddr, TryPeerError)>()
            .map(|(_, v)| stream::iter_ok(v))
            .flatten()
            .into_boxed()
        } else {
            future::empty().into_stream().into_boxed()
        };

        let timeout = {
            Timeout::new(Duration::from_secs(10), &handle)
            .map_err(BootstrapError::TimerIo)
        }?;
        Ok(stream::iter_ok(peers)
            .chain(sd_peers)
            .filter(move |addr| {
                !blacklist.contains(addr)
            })
            .map(move |addr| {
                try_peer(&handle, &addr, our_uid, name_hash, ext_reachability.clone())
                .map_err(move |e| (addr, e))
            })
            .buffer_unordered(64)
            .until(timeout.infallible())
            .first_ok()
            .map_err(|errs| {
                BootstrapError::AllPeersFailed(errs.into_iter().collect())
            })
        )
    };
    future::result(try()).flatten().into_boxed()
}

