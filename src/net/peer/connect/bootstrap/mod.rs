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
use config_file_handler;
use net::peer::connect::bootstrap::cache::Cache;
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
) -> BoxFuture<Peer<UID>, BootstrapError> {
    let config = config.clone();
    let handle = handle.clone();
    let try = || -> Result<_, BootstrapError> {
        let sd_peers = if use_service_discovery {
            let sd_port = config.read().service_discovery_port.unwrap_or(
                service::SERVICE_DISCOVERY_DEFAULT_PORT,
            );
            service_discovery::discover::<Vec<PaAddr>>(&handle, sd_port)
                .map_err(BootstrapError::ServiceDiscovery)?
                .infallible::<(PaAddr, TryPeerError)>()
                .map(|(_, v)| stream::iter_ok(v))
                .flatten()
                // TODO(povilas): remove this when service discovery returns peer public key
                .map(PeerInfo::with_rand_key)
                .into_boxed()
        } else {
            future::empty().into_stream().into_boxed()
        };
        let sd_peers = {
            let timeout = Duration::from_millis(SERVICE_DISCOVERY_TIMEOUT_MS);
            sd_peers.until(Timeout::new(timeout, &handle).infallible())
        };

        let peers = bootstrap_peers(&config)?;
        let timeout = Timeout::new(Duration::from_secs(BOOTSTRAP_TIMEOUT_SEC), &handle);
        let mut i = 0;
        Ok(
            sd_peers
                .chain(stream::iter_ok(peers))
                .filter(move |peer| !blacklist.contains(&peer.addr))
                .map(move |peer| {
                    // TODO(canndrew): come up with a more reliable way to avoid bootstrapping to
                    // the same peer multiple times. This can cause the different peers using the
                    // compat API to choose different connections. We also shouldn't bootstrap to
                    // all addresses simultaneously.
                    let delay = Timeout::new(Duration::from_millis(200) * i, &handle);
                    i += 1;
                    let config = config.clone();
                    let handle = handle.clone();
                    let our_sk = our_sk.clone();
                    let request = request.clone();

                    delay.infallible().and_then(move |()| {
                        try_peer(
                            &handle,
                            &peer.addr,
                            &config,
                            request,
                            our_sk,
                            peer.pub_key,
                        )
                            .map_err(move |e| (peer.addr, e))
                    })
                })
                .buffer_unordered(64)
                .until(timeout.infallible())
                .first_ok()
                .map_err(|errs| {
                    BootstrapError::AllPeersFailed(errs.into_iter().collect())
                }),
        )
    };
    future::result(try()).flatten().into_boxed()
}

/// Collects bootstrap peers from cache and config.
fn bootstrap_peers(config: &ConfigFile) -> Result<Vec<PeerInfo>, BootstrapError> {
    let config = config.read();
    let mut cache = Cache::new(config.bootstrap_cache_name.as_ref().map(|p| p.as_ref()))?;
    let mut peers = Vec::new();
    peers.extend(cache.read_file());
    peers.extend(config.hard_coded_contacts.clone());
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod bootstrap_peers {
        use super::*;
        use config::PeerInfo;
        use util::write_bootstrap_cache_to_tmp_file;

        #[test]
        fn it_returns_hard_coded_contacts_and_addresses_from_cache() {
            let bootstrap_cache = write_bootstrap_cache_to_tmp_file(
                br#"
                [
                    {
                      "addr": "tcp://1.2.3.5:5000",
                      "pub_key": [1, 2, 3]
                    }
                ]
            "#,
            );
            let config = unwrap!(ConfigFile::new_temporary());

            {
                let mut conf_write = unwrap!(config.write());
                conf_write.hard_coded_contacts =
                    vec![PeerInfo::with_rand_key(tcp_addr!("1.2.3.4:4000"))];
                conf_write.bootstrap_cache_name = Some(Path::new(&bootstrap_cache).to_path_buf());
            }

            let peers: Vec<PaAddr> = unwrap!(bootstrap_peers(&config))
                .iter()
                .map(|peer| peer.addr)
                .collect();

            assert!(peers.contains(&PaAddr::Tcp(addr!("1.2.3.4:4000"))));
            assert!(peers.contains(&PaAddr::Tcp(addr!("1.2.3.5:5000"))));
        }
    }
}
