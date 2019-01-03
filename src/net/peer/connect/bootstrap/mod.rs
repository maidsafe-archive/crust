// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod cache;
mod try_peer;

pub use self::try_peer::{ConnectHandshakeError, TryPeerError};
use crate::config::PeerInfo;
pub use crate::net::peer::connect::bootstrap::cache::{Cache, CacheError};
use crate::net::peer::connect::bootstrap::try_peer::try_peer;
use crate::net::peer::connect::handshake_message::BootstrapRequest;
use crate::net::service_discovery;
use crate::priv_prelude::*;
use crate::service;
use rand::{thread_rng, Rng};

const SERVICE_DISCOVERY_TIMEOUT_MS: u64 = 200;
const BOOTSTRAP_TIMEOUT_SEC: u64 = 10;

quick_error! {
    /// Error returned when bootstrapping fails.
    #[derive(Debug)]
    pub enum BootstrapError {
        ServiceDiscovery(e: io::Error) {
            description("IO error using service discovery")
            display("IO error using service discovery: {}", e)
            cause(e)
        }
        AllPeersFailed(e: HashMap<PaAddr, TryPeerError>) {
            description("Failed to connect to any bootstrap peer")
            display("Failed to connect to any bootstrap peer. \
                    All {} attempts failed. Errors: {:?}", e.len(), e)
        }
    }
}

/// Try to bootstrap to the network.
///
/// On success, returns the first peer that we've bootstrapped to.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap(
    handle: &Handle,
    request: BootstrapRequest,
    blacklist: HashSet<PaAddr>,
    use_service_discovery: bool,
    config: &ConfigFile,
    our_sk: &SecretEncryptKey,
    our_pk: &PublicEncryptKey,
    cache: &Cache,
) -> BoxFuture<Peer, BootstrapError> {
    let config = config.clone();
    let cache = cache.clone();

    let sd_peers = if use_service_discovery {
        discover_peers_on_lan(handle, &config, our_sk, our_pk)
    } else {
        future::ok(stream::empty().into_boxed()).into_boxed()
    };
    let cached_peers = shuffle_vec(cache.peers_vec());
    let hard_coded_peers = shuffle_vec(config.read().hard_coded_contacts.clone());

    let handle1 = handle.clone();
    let handle2 = handle.clone();
    sd_peers
        .and_then(move |sd_peers| {
            let mut i = 0;

            sd_peers
                .chain(stream::iter_ok(cached_peers))
                .chain(stream::iter_ok(hard_coded_peers))
                .filter(move |peer| !blacklist.contains(&peer.addr))
                .filter(move |peer| peer.addr.is_tcp()) // we don't use uTP to bootstrap
                .map(move |peer| {
                    let fut = bootstrap_to_peer(&handle1, peer, i, &config, &cache, &request);
                    i += 1;
                    fut
                }).buffer_unordered(64)
                .with_timeout(Duration::from_secs(BOOTSTRAP_TIMEOUT_SEC), &handle2)
                .first_ok()
                .map_err(|errs| BootstrapError::AllPeersFailed(errs.into_iter().collect()))
        })
        .into_boxed()
}

fn discover_peers_on_lan(
    handle: &Handle,
    config: &ConfigFile,
    our_sk: &SecretEncryptKey,
    our_pk: &PublicEncryptKey,
) -> BoxFuture<BoxStream<PeerInfo, (PaAddr, TryPeerError)>, BootstrapError> {
    let handle = handle.clone();
    let sd_port = config
        .read()
        .service_discovery_port
        .unwrap_or(service::SERVICE_DISCOVERY_DEFAULT_PORT);

    service_discovery::discover::<Vec<PeerInfo>>(&handle, sd_port, our_sk.clone(), *our_pk)
        .map_err(BootstrapError::ServiceDiscovery)
        .map(move |s| {
            s.map(|(_, v)| stream::iter_ok(v))
                .flatten()
                .with_timeout(Duration::from_millis(SERVICE_DISCOVERY_TIMEOUT_MS), &handle)
                .infallible()
                .into_boxed()
        })
        .into_boxed()
}

/// Attempts to bootstrap to single given peer.
fn bootstrap_to_peer(
    handle: &Handle,
    peer: PeerInfo,
    peer_nr: u32,
    config: &ConfigFile,
    cache: &Cache,
    request: &BootstrapRequest,
) -> BoxFuture<Peer, (PaAddr, TryPeerError)> {
    let config = config.clone();
    let handle = handle.clone();
    let request = request.clone();
    let cache = cache.clone();
    let cache2 = cache.clone();
    let peer2 = peer.clone();

    // TODO(canndrew): come up with a more reliable way to avoid bootstrapping to the
    // same peer multiple times. This can cause the different peers using the compat
    // API to choose different connections. We also shouldn't bootstrap to all
    // addresses simultaneously.
    let delay = Timeout::new(Duration::from_millis(200) * peer_nr, &handle);
    delay
        .infallible()
        .and_then(move |()| {
            try_peer(&handle, &peer.addr, &config, request, peer.pub_key)
                .map(move |peer_conn| {
                    cache.put(&peer);
                    let _ = cache
                        .commit()
                        .map_err(|e| error!("Failed to commit bootstrap cache: {}", e));
                    peer_conn
                })
                .map_err(move |e| {
                    cache2.remove(&peer2);
                    let _ = cache2
                        .commit()
                        .map_err(|e| error!("Failed to commit bootstrap cache: {}", e));
                    (peer2.addr, e)
                })
        })
        .into_boxed()
}

/// Randomly shuffle vector items and return the vector.
fn shuffle_vec<T>(mut v: Vec<T>) -> Vec<T> {
    thread_rng().shuffle(&mut v);
    v
}
