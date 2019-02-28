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
use lru_time_cache::LruCache;
use safe_crypto::PublicEncryptKey;
use std::ffi::OsString;

/// Bootstrap cache specific configurable settings.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct CacheConfig {
    /// File path for bootstrap cache.
    pub file_name: Option<OsString>,
    /// Maximum number of node contacts that will be cached for bootstrap.
    pub max_size: usize,
}

impl Default for CacheConfig {
    fn default() -> CacheConfig {
        CacheConfig {
            file_name: None,
            max_size: 200,
        }
    }
}

/// Bootstrap cache - keeps log of known publicly accessible peers.
/// This cache can optionally be stored on disk and loaded later.
#[derive(Clone)]
pub struct Cache {
    file_name: Option<OsString>,
    peers: LruCache<PublicEncryptKey, PeerInfo>,
}

impl Cache {
    /// Constructs new bootstrap cache. You can optionally specify the file name which will
    /// be used to read/write the cache to. If no file name is given, the default path is used, see
    /// `#get_default_file_name()`.
    pub fn new(cfg: CacheConfig) -> Self {
        Cache {
            file_name: cfg.file_name,
            peers: LruCache::with_capacity(cfg.max_size),
        }
    }

    /// Default bootstrap cache file name is executable file + '.bootstrap.cache' suffix.
    pub fn get_default_file_name() -> crate::Res<OsString> {
        let mut name = config_file_handler::exe_file_stem()?;
        name.push(".bootstrap.cache");
        Ok(name)
    }

    /// Updates cache by reading it from file and returns the current list of peers.
    pub fn read_file(&mut self) {
        match self.open_file() {
            Ok(file_handler) => {
                let mut peers = file_handler.read_file().unwrap_or_else(|e| {
                    info!("Failed to read bootstrap cache file: {}", e);
                    Default::default()
                });
                for peer in peers.drain(..).rev() {
                    let _ = self.peers.insert(peer.pub_key, peer);
                }
            }
            Err(e) => info!("Failed to open bootstrap cache file: {}", e),
        }
    }

    /// Inserts given peer to the cache. If peer is already cached, it is moved to cache front.
    /// If cache is full, last recently used peer is removed.
    pub fn put(&mut self, peer: PeerInfo) {
        let _ = self.peers.insert(peer.pub_key, peer);
    }

    /// Removes given peer from the cache.
    pub fn remove(&mut self, peer: &PeerInfo) {
        let _ = self.peers.remove(&peer.pub_key);
    }

    /// Writes bootstrap cache to disk.
    pub fn commit(&self) -> crate::Res<()> {
        let file_handler = self.open_file()?;
        file_handler.write_file(&self.peers())?;
        Ok(())
    }

    /// Calls `commit()` and if error happens just logs it.
    pub fn try_commit(&self) {
        if let Err(e) = self.commit() {
            info!("Failed to write bootstrap cache to disk: {}", e);
        }
    }

    /// Returns cached peers in the most recently used order.
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.peers.peek_iter().map(|(_, peer)| *peer).collect()
    }

    fn open_file(&self) -> crate::Res<FileHandler<Vec<PeerInfo>>> {
        let fname = self
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
                let mut cache = Cache::new(CacheConfig {
                    file_name: Some(fname),
                    max_size: 5,
                });

                cache.read_file();

                let addrs: Vec<_> = cache.peers().iter().map(|peer| peer.addr).collect();
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 4, 4000)));
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 5, 5000)));
            }
        }

        mod put {
            use super::*;

            #[test]
            fn it_inserts_given_peer_to_the_front() {
                let mut cache = Cache::new(CacheConfig {
                    file_name: None,
                    max_size: 5,
                });

                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000)));
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 5, 5000)));

                let addrs: Vec<SocketAddr> =
                    cache.peers.iter().map(|(_, peer)| peer.addr).collect();
                assert_eq!(addrs.len(), 2);
                assert_eq!(addrs[0], ipv4_addr(1, 2, 3, 5, 5000));
                assert_eq!(addrs[1], ipv4_addr(1, 2, 3, 4, 4000));
            }

            #[test]
            fn when_peer_is_already_cached_it_is_moved_to_front() {
                let mut cache = Cache::new(CacheConfig {
                    file_name: None,
                    max_size: 5,
                });
                let peer1 = peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000));
                cache.put(peer1);
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 5, 5000)));

                cache.put(peer1);

                let addrs: Vec<SocketAddr> =
                    cache.peers.iter().map(|(_, peer)| peer.addr).collect();
                assert_eq!(addrs.len(), 2);
                assert_eq!(addrs[0], ipv4_addr(1, 2, 3, 4, 4000));
                assert_eq!(addrs[1], ipv4_addr(1, 2, 3, 5, 5000));
            }

            #[test]
            fn when_cache_is_full_given_peer_is_added_and_last_one_is_removed() {
                let mut cache = Cache::new(CacheConfig {
                    file_name: None,
                    max_size: 2,
                });
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000)));
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 5, 5000)));

                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 6, 6000)));

                let addrs: Vec<SocketAddr> =
                    cache.peers.iter().map(|(_, peer)| peer.addr).collect();
                assert_eq!(addrs.len(), 2);
                assert_eq!(addrs[0], ipv4_addr(1, 2, 3, 6, 6000));
                assert_eq!(addrs[1], ipv4_addr(1, 2, 3, 5, 5000));
            }
        }

        #[test]
        fn remove() {
            let mut cache = Cache::new(CacheConfig {
                file_name: None,
                max_size: 2,
            });
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
                let mut cache = Cache::new(CacheConfig {
                    file_name: Some(tmp_fname.clone()),
                    max_size: 5,
                });
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000)));
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 5, 5000)));

                unwrap!(cache.commit());

                let mut cache = Cache::new(CacheConfig {
                    file_name: Some(tmp_fname.clone()),
                    max_size: 5,
                });
                cache.read_file();
                let addrs: Vec<_> = cache.peers().iter().map(|peer| peer.addr).collect();
                assert_eq!(addrs.len(), 2);
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 4, 4000)));
                assert!(addrs.contains(&ipv4_addr(1, 2, 3, 5, 5000)));
            }

            #[test]
            fn it_retains_cached_items_order() {
                let tmp_fname: OsString = bootstrap_cache_tmp_file().into();
                let mut cache = Cache::new(CacheConfig {
                    file_name: Some(tmp_fname.clone()),
                    max_size: 5,
                });
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 6, 6000)));
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000)));
                cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 5, 5000)));

                unwrap!(cache.commit());

                let mut cache = Cache::new(CacheConfig {
                    file_name: Some(tmp_fname),
                    max_size: 5,
                });
                cache.read_file();
                let addrs: Vec<_> = cache.peers().iter().map(|peer| peer.addr).collect();
                assert_eq!(addrs.len(), 3);
                assert_eq!(addrs[0], ipv4_addr(1, 2, 3, 5, 5000));
                assert_eq!(addrs[1], ipv4_addr(1, 2, 3, 4, 4000));
                assert_eq!(addrs[2], ipv4_addr(1, 2, 3, 6, 6000));
            }
        }
    }
}
