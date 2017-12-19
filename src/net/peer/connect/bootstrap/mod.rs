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

use config_file_handler;
use net::peer::connect::bootstrap::cache::Cache;
use net::peer::connect::bootstrap::try_peer::try_peer;
use net::service_discovery;

use priv_prelude::*;
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
    our_uid: UID,
    name_hash: NameHash,
    ext_reachability: ExternalReachability,
    blacklist: HashSet<PaAddr>,
    use_service_discovery: bool,
    config: &ConfigFile,
) -> BoxFuture<Peer<UID>, BootstrapError> {
    let config = config.clone();
    let handle = handle.clone();
    let try = || -> Result<_, BootstrapError> {
        let mut peers = Vec::new();
        let mut cache = Cache::new(config.read().bootstrap_cache_name.as_ref().map(
            |p| p.as_ref(),
        ))?;
        peers.extend(cache.read_file());
        peers.extend(config.read().hard_coded_contacts.iter().cloned());

        let sd_peers = if use_service_discovery {
            let sd_port = config.read().service_discovery_port.unwrap_or(
                service::SERVICE_DISCOVERY_DEFAULT_PORT,
            );
            service_discovery::discover::<Vec<PaAddr>>(&handle, sd_port)
                .map_err(BootstrapError::ServiceDiscovery)?
                .infallible::<(PaAddr, TryPeerError)>()
                .map(|(_, v)| stream::iter_ok(v))
                .flatten()
                .into_boxed()
        } else {
            future::empty().into_stream().into_boxed()
        };

        let timeout = Timeout::new(Duration::from_secs(BOOTSTRAP_TIMEOUT_SEC), &handle);
        Ok(
            stream::iter_ok(peers)
                .chain(sd_peers)
                .filter(move |addr| !blacklist.contains(addr))
                .map(move |addr| {
                    try_peer(
                        &handle,
                        &addr,
                        our_uid,
                        name_hash,
                        ext_reachability.clone(),
                        &config,
                    )
                        .map_err(move |e| (addr, e))
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
