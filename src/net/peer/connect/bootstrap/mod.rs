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
pub fn bootstrap(
    handle: &Handle,
    request: BootstrapRequest,
    blacklist: HashSet<PaAddr>,
    use_service_discovery: bool,
    config: &ConfigFile,
    our_sk: SecretKey,
    cache: &Cache,
) -> BoxFuture<Peer, BootstrapError> {
    let our_pk = request.uid.pkey();
    let config = config.clone();
    let handle = handle.clone();
    let cache = cache.clone();

    let handle1 = handle.clone();
    let handle2 = handle.clone();
    let sd_peers = if use_service_discovery {
        let sd_port = config
            .read()
            .service_discovery_port
            .unwrap_or(service::SERVICE_DISCOVERY_DEFAULT_PORT);
        service_discovery::discover::<Vec<PeerInfo>>(&handle, sd_port, our_pk, our_sk.clone())
            .map_err(BootstrapError::ServiceDiscovery)
            .map(move |s| {
                s.map(|(_, v)| stream::iter_ok(v))
                    .flatten()
                    .with_timeout(
                        Duration::from_millis(SERVICE_DISCOVERY_TIMEOUT_MS),
                        &handle1,
                    )
                    .infallible()
                    .into_boxed()
            })
            .into_boxed()
    } else {
        future::ok(stream::empty().into_boxed()).into_boxed()
    };

    let cached_peers = future::result(bootstrap_peers(&config, &cache));

    sd_peers
        .join(cached_peers)
        .and_then(move |(sd_peers, cached_peers)| {
            let mut i = 0;

            sd_peers
                .chain(stream::iter_ok(cached_peers))
                .filter(move |peer| !blacklist.contains(&peer.addr))
                .map(move |peer| {
                    let fut =
                        bootstrap_to_peer(&handle2, peer, i, &config, &cache, &request, &our_sk);
                    i += 1;
                    fut
                })
                .buffer_unordered(64)
                .with_timeout(Duration::from_secs(BOOTSTRAP_TIMEOUT_SEC), &handle)
                .first_ok()
                .map_err(|errs| BootstrapError::AllPeersFailed(errs.into_iter().collect()))
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
    our_sk: &SecretKey,
) -> BoxFuture<Peer, (PaAddr, TryPeerError)> {
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

/// Collects bootstrap peers from cache and config.
fn bootstrap_peers(config: &ConfigFile, cache: &Cache) -> Result<Vec<PeerInfo>, BootstrapError> {
    let mut peers = Vec::new();
    peers.extend(cache.peers());
    peers.extend(config.read().hard_coded_contacts.clone());
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod bootstrap_peers {
        use super::*;
        use config::PeerInfo;
        use util::bootstrap_cache_tmp_file;

        #[test]
        fn it_returns_hard_coded_contacts_and_addresses_from_cache() {
            let config = unwrap!(ConfigFile::new_temporary());
            unwrap!(config.write()).hard_coded_contacts =
                vec![PeerInfo::with_rand_key(tcp_addr!("1.2.3.4:4000"))];
            let cache = unwrap!(Cache::new(Some(&bootstrap_cache_tmp_file())));
            cache.put(&PeerInfo::with_rand_key(tcp_addr!("1.2.3.5:5000")));

            let peers: Vec<PaAddr> = unwrap!(bootstrap_peers(&config, &cache))
                .iter()
                .map(|peer| peer.addr)
                .collect();

            assert!(peers.contains(&tcp_addr!("1.2.3.4:4000")));
            assert!(peers.contains(&tcp_addr!("1.2.3.5:5000")));
        }
    }
}
