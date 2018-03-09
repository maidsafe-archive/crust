// Copyright 2016 MaidSafe.net limited.
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

use config::PeerInfo;
use config_file_handler::{self, FileHandler};
use priv_prelude::*;
use std::rc::Rc;
use std::sync::Mutex;

quick_error! {
    /// Bootstrap cache error
    #[derive(Debug)]
    pub enum CacheError {
        /// File related error: read or write.
        Io(e: config_file_handler::Error) {
            description("Failed to access bootstrap cache file")
            display("Failed to access bootstrap cache file: {}", e)
            cause(e)
            from()
        }
    }
}

/// Reference-counted bootstrap cache - keeps log of known publicly accessible peers.
#[derive(Clone)]
pub struct Cache {
    inner: Rc<Mutex<Inner>>,
}

struct Inner {
    file_handler: FileHandler<HashSet<PeerInfo>>,
    peers: HashSet<PeerInfo>,
}

impl Cache {
    pub fn new(name: Option<&OsStr>) -> Result<Self, CacheError> {
        let inner = Inner {
            file_handler: FileHandler::new(name.unwrap_or(&Self::default_file_name()?), true)?,
            peers: HashSet::new(),
        };
        Ok(Cache { inner: Rc::new(Mutex::new(inner)) })
    }

    pub fn default_file_name() -> Result<OsString, CacheError> {
        let mut name = config_file_handler::exe_file_stem()?;
        name.push(".bootstrap.cache");
        Ok(name)
    }

    /// Updates cache by reading it from file and returns the current snapshot of peers.
    pub fn read_file(&self) {
        let mut inner = unwrap!(self.inner.lock());
        inner.peers = inner.file_handler.read_file().ok().unwrap_or_else(
            HashSet::new,
        );
    }

    /// Writes bootstrap cache to disk.
    pub fn commit(&self) -> Result<(), CacheError> {
        let inner = unwrap!(self.inner.lock());
        inner.file_handler.write_file(&inner.peers).map_err(
            CacheError::Io,
        )
    }

    /// Inserts given peer to the cache.
    pub fn put(&self, peer: &PeerInfo) {
        let mut inner = unwrap!(self.inner.lock());
        let _ = inner.peers.insert(peer.clone());
    }

    /// Removes given peer from the cache.
    pub fn remove(&self, peer: &PeerInfo) {
        let mut inner = unwrap!(self.inner.lock());
        let _ = inner.peers.remove(peer);
    }

    /// Returns current snapshot of peers in the cache.
    pub fn peers(&self) -> HashSet<PeerInfo> {
        let inner = unwrap!(self.inner.lock());
        inner.peers.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod cache {
        use super::*;
        use hamcrest::prelude::*;
        use util::bootstrap_cache_tmp_file;

        mod read_file {
            use super::*;
            use util::write_bootstrap_cache_to_tmp_file;

            #[test]
            fn it_reads_peer_info_from_json_formatted_file() {
                let fname = write_bootstrap_cache_to_tmp_file(
                    br#"
                    [
                        {
                          "addr": "tcp://1.2.3.4:4000",
                          "pub_key": [1, 2, 3]
                        },
                        {
                          "addr": "utp://1.2.3.5:5000",
                          "pub_key": [3, 2, 1]
                        }
                    ]
                "#,
                );
                let cache = unwrap!(Cache::new(Some(&fname)));

                cache.read_file();

                let addrs: Vec<PaAddr> = cache.peers().iter().map(|peer| peer.addr).collect();
                assert!(addrs.contains(&tcp_addr!("1.2.3.4:4000")));
                assert!(addrs.contains(&utp_addr!("1.2.3.5:5000")));
            }
        }

        #[test]
        fn put() {
            let cache = unwrap!(Cache::new(Some(&bootstrap_cache_tmp_file())));

            cache.put(&PeerInfo::with_rand_key(tcp_addr!("1.2.3.4:4000")));
            cache.put(&PeerInfo::with_rand_key(tcp_addr!("1.2.3.5:5000")));

            let peers: Vec<PaAddr> = cache.peers().iter().map(|peer| peer.addr).collect();
            assert_that!(
                &peers,
                contains(vec![tcp_addr!("1.2.3.4:4000"), tcp_addr!("1.2.3.5:5000")]).exactly()
            );
        }

        #[test]
        fn remove() {
            let cache = unwrap!(Cache::new(Some(&bootstrap_cache_tmp_file())));
            let peer = PeerInfo::with_rand_key(tcp_addr!("1.2.3.4:4000"));
            cache.put(&peer);

            cache.remove(&peer);

            assert!(cache.peers().is_empty());
        }

        mod commit {
            use super::*;

            #[test]
            fn it_writes_cache_to_file() {
                let tmp_fname = bootstrap_cache_tmp_file();
                let cache = unwrap!(Cache::new(Some(&tmp_fname)));
                cache.put(&PeerInfo::with_rand_key(tcp_addr!("1.2.3.4:4000")));
                cache.put(&PeerInfo::with_rand_key(tcp_addr!("1.2.3.5:5000")));

                unwrap!(cache.commit());

                let cache = unwrap!(Cache::new(Some(&tmp_fname)));
                cache.read_file();
                let peers: Vec<PaAddr> = cache.peers().iter().map(|peer| peer.addr).collect();
                assert_that!(
                    &peers,
                    contains(vec![tcp_addr!("1.2.3.4:4000"), tcp_addr!("1.2.3.5:5000")]).exactly()
                );
            }
        }
    }
}
