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

mod cache;
mod try_peer;

pub use self::try_peer::{ConnectHandshakeError, TryPeerError};
use config::PeerInfo;
pub use net::peer::connect::bootstrap::cache::{Cache, CacheError};
use net::peer::connect::bootstrap::try_peer::try_peer;
use net::peer::connect::handshake_message::BootstrapRequest;
use net::service_discovery;
use priv_prelude::*;
use rand::{thread_rng, Rng};
use rust_sodium::crypto::box_::SecretKey;
use service;

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
pub fn bootstrap<UID: Uid>(
    handle: &Handle,
    request: BootstrapRequest<UID>,
    blacklist: HashSet<PaAddr>,
    use_service_discovery: bool,
    config: &ConfigFile,
    our_sk: SecretKey,
    cache: &Cache,
) -> BoxFuture<Peer<UID>, BootstrapError> {
    let our_pk = request.their_pk;
    let config = config.clone();
    let cache = cache.clone();

    let sd_peers = if use_service_discovery {
        discover_peers_on_lan(handle, &config, &our_sk, our_pk)
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
                .map(move |peer| {
                    let fut =
                        bootstrap_to_peer(&handle1, peer, i, &config, &cache, &request, &our_sk);
                    i += 1;
                    fut
                })
                .buffer_unordered(64)
                .with_timeout(Duration::from_secs(BOOTSTRAP_TIMEOUT_SEC), &handle2)
                .first_ok()
                .map_err(|errs| BootstrapError::AllPeersFailed(errs.into_iter().collect()))
        })
        .into_boxed()
}

fn discover_peers_on_lan(
    handle: &Handle,
    config: &ConfigFile,
    our_sk: &SecretKey,
    our_pk: PublicKey,
) -> BoxFuture<BoxStream<PeerInfo, (PaAddr, TryPeerError)>, BootstrapError> {
    let handle = handle.clone();
    let our_sk = our_sk.clone();
    let sd_port = config
        .read()
        .service_discovery_port
        .unwrap_or(service::SERVICE_DISCOVERY_DEFAULT_PORT);

    service_discovery::discover::<Vec<PeerInfo>>(&handle, sd_port, our_pk, our_sk)
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
fn bootstrap_to_peer<UID: Uid>(
    handle: &Handle,
    peer: PeerInfo,
    peer_nr: u32,
    config: &ConfigFile,
    cache: &Cache,
    request: &BootstrapRequest<UID>,
    our_sk: &SecretKey,
) -> BoxFuture<Peer<UID>, (PaAddr, TryPeerError)> {
    let config = config.clone();
    let handle = handle.clone();
    let our_sk = our_sk.clone();
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
            try_peer(&handle, &peer.addr, &config, request, our_sk, peer.pub_key)
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
