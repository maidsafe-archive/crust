// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::PeerInfo;
use config_file_handler::{self, FileHandler};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::rc::Rc;
use std::time::Instant;

const BOOTSTRAP_CACHE_DEFAULT_LIMIT: usize = 1500;

/// Reference-counted bootstrap cache - keeps log of known publicly accessible peers.
#[derive(Clone)]
pub struct Cache {
    // TODO(povilas): remove Rc and store bootstrap cache in Core
    inner: Rc<RefCell<Inner>>,
}

struct Inner {
    file_name: Option<OsString>,
    cache_limit: usize,
    peers: HashMap<PeerInfo, Instant>,
}

impl Cache {
    /// Constructs new bootstrap cache. You can optionally specify the file name which will
    /// be used to read/write the cache to, or the cache limit which defines the maximum number
    /// of peers that can be stored. If no file name is give, the default path is used, see
    /// `#get_default_file_name()`.
    pub fn new(file_name: Option<OsString>, cache_limit: Option<usize>) -> Self {
        let cache_limit = cache_limit.unwrap_or(BOOTSTRAP_CACHE_DEFAULT_LIMIT);
        let inner = Inner {
            file_name,
            cache_limit,
            peers: HashMap::with_capacity(cache_limit),
        };
        Cache {
            inner: Rc::new(RefCell::new(inner)),
        }
    }

    /// Default bootstrap cache file name is executable file + '.bootstrap.cache' suffix.
    pub fn get_default_file_name() -> crate::Res<OsString> {
        let mut name = config_file_handler::exe_file_stem()?;
        name.push(".bootstrap.cache");
        Ok(name)
    }

    /// Updates cache by reading it from file and returns the current snapshot of peers.
    pub fn read_file(&self) {
        match self.open_file() {
            Ok(file_handler) => {
                let mut inner = self.inner.borrow_mut();
                let peers = file_handler.read_file().unwrap_or_else(|e| {
                    info!("Failed to read bootstrap cache file: {}", e);
                    HashSet::new()
                });

                inner.peers = HashMap::with_capacity(inner.cache_limit);
                for peer in peers {
                    let _ = inner.peers.insert(peer, Instant::now());
                }
            }
            Err(e) => info!("Failed to open bootstrap cache file: {}", e),
        }
    }

    /// Inserts given peer to the cache. If the peer already exists, it updates the entry's `Instant.
    /// If the cache has reached full capacity, remove inactive peers and then add `peer`.
    pub fn put(&self, peer: PeerInfo) {
        let (peers_len, cache_limit) = {
            let inner = self.inner.borrow();
            (inner.peers.len(), inner.cache_limit)
        };

        if peers_len >= cache_limit {
            warn!("Bootstrap cache reached limit, removing least active peers...");
            self.clear_inactive_peers();
        }

        let mut inner = self.inner.borrow_mut();
        let _ = inner.peers.entry(peer).or_insert(Instant::now());
    }

    /// Removes inactive peers from the cache.
    /// TODO(1uka): configure how many peers to keep
    pub fn clear_inactive_peers(&self) {
        let mut inner = self.inner.borrow_mut();
        let mut peers: Vec<_> = inner.peers.drain().collect();

        peers.sort_by_key(|(_, instant)| instant.elapsed());
        let n_peers = (inner.cache_limit as f32 * 0.10).ceil() as usize;

        inner.peers = peers.into_iter().take(n_peers).collect();
    }

    /// Removes given peer from the cache.
    pub fn remove(&self, peer: &PeerInfo) {
        let mut inner = self.inner.borrow_mut();
        let _ = inner.peers.remove(peer);
    }

    /// Writes bootstrap cache to disk.
    pub fn commit(&self) -> crate::Res<()> {
        let file_handler = self.open_file()?;
        let peers = self.peers();
        file_handler.write_file(&peers)?;
        Ok(())
    }

    /// Returns current snapshot of peers in the cache.
    pub fn peers(&self) -> HashSet<PeerInfo> {
        self.inner
            .borrow()
            .peers
            .keys()
            .map(|peer| peer.clone())
            .collect()
    }

    fn open_file(&self) -> crate::Res<FileHandler<HashSet<PeerInfo>>> {
        let inner = self.inner.borrow_mut();
        let fname = inner
            .file_name
            .as_ref()
            .cloned()
            .unwrap_or(Self::get_default_file_name()?);
        Ok(FileHandler::new(&fname, true)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod cache {
        use super::*;
        use crate::common::ipv4_addr;
        use crate::tests::utils::{bootstrap_cache_tmp_file, peer_info_with_rand_key};
        use std::fs::File;
        use std::io::Write;
        use std::net::SocketAddr;

        /// # Arguments
        ///
        /// * `content` - json formatted bootstrap cache to be written to file.
        ///
        /// # Returns
        ///
        /// file name where content was written to.
        fn write_bootstrap_cache_to_tmp_file(content: &[u8]) -> OsString {
            let path = bootstrap_cache_tmp_file();
            let mut f = unwrap!(File::create(path.clone()));
            unwrap!(f.write_all(content));
            path.into()
        }

        mod read_file {
            use super::*;

            #[test]
            fn it_reads_peer_info_from_json_formatted_file() {
                let fname = write_bootstrap_cache_to_tmp_file(
                    br#"
                    [
                        {
                          "addr": "1.2.3.4:4000",
                          "pub_key": {
                            "encrypt": [
                              66, 192, 123, 121, 77, 106, 241, 176,
                              72, 130, 194, 59, 168, 159, 4, 80,
                              228, 99, 54, 157, 223, 111, 169, 176,
                              149, 150, 249, 11, 165, 242, 193, 44
                            ]
                          }
                        },
                        {
                          "addr": "1.2.3.5:5000",
                          "pub_key": {
                            "encrypt": [
                              51, 217, 206, 79, 229, 2, 54, 135,
                              40, 80, 53, 184, 71, 196, 201, 37,
                              181, 212, 185, 162, 185, 228, 136, 230,
                              197, 53, 46, 242, 163, 157, 235, 103
                            ]
                          }
                        }
                    ]
                "#,
                );
                let cache = Cache::new(Some(fname), None);

                cache.read_file();

                let addrs: Vec<SocketAddr> = cache.peers().iter().map(|peer| peer.addr).collect();
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 4, 4000)));
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 5, 5000)));
            }
        }

        mod put {
            use super::*;

            #[test]
            fn it_stores_peers() {
                let cache = Cache::new(None, None);

                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000)));
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 5, 5000)));

                let addrs: Vec<SocketAddr> = cache.peers().iter().map(|peer| peer.addr).collect();
                assert_eq!(addrs.len(), 2);
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 4, 4000)));
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 5, 5000)));
            }

            #[test]
            fn it_doesnt_overflow_nor_wipe_cache() {
                let cache_limit = 2;
                let cache = Cache::new(None, Some(cache_limit));

                (0..3)
                    .map(|i| peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, i)))
                    .for_each(|peer| cache.put(peer));

                let peers_len = cache.peers().len();

                assert!(peers_len <= cache_limit);
                assert!(peers_len > 0);
            }
        }

        mod clear_inactive {
            use super::*;

            use std::thread::sleep;
            use std::time::Duration;

            #[test]
            fn it_removes_least_recent_peers() {
                let cache_limit = 3;
                let cache = Cache::new(None, Some(cache_limit));

                let interval = Duration::new(0, 100);
                (0..4)
                    .map(|i| {
                        sleep(interval);
                        peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, i))
                    })
                    .for_each(|peer| cache.put(peer));

                let cache_peers = cache.peers();
                let addrs: Vec<SocketAddr> = cache_peers.iter().map(|peer| peer.addr).collect();

                /// Cache was cleared because if was full
                assert!(cache_peers.len() < cache_limit);
                /// Oldest peers were removed (in this test the first peer we inserted is the oldest)
                assert!(!addrs.contains(&ipv4_addr(1, 2, 3, 4, 0)));
                /// Most recent peers were preserved (in this test it's the last peer)
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 4, 3)));
            }
        }

        #[test]
        fn remove() {
            let cache = Cache::new(None, None);
            let peer = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
            cache.put(peer);

            cache.remove(&peer);

            assert!(cache.peers().is_empty());
        }

        mod commit {
            use super::*;

            #[test]
            fn it_writes_cache_to_file() {
                let tmp_fname: OsString = bootstrap_cache_tmp_file().into();
                let cache = Cache::new(Some(tmp_fname.clone()), None);
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000)));
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 5, 5000)));

                unwrap!(cache.commit());

                let cache = Cache::new(Some(tmp_fname), None);
                cache.read_file();
                let addrs: Vec<SocketAddr> = cache.peers().iter().map(|peer| peer.addr).collect();
                assert_eq!(addrs.len(), 2);
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 4, 4000)));
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 5, 5000)));
            }
        }
    }
}
