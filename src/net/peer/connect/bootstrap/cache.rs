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

pub struct Cache {
    file_handler: FileHandler<Vec<PeerInfo>>,
}

impl Cache {
    pub fn new(name: Option<&Path>) -> Result<Self, config_file_handler::Error> {
        Ok(Cache {
            file_handler: FileHandler::new(name.unwrap_or(&Self::default_file_name()?), true)?,
        })
    }

    pub fn default_file_name() -> Result<PathBuf, config_file_handler::Error> {
        let mut name = config_file_handler::exe_file_stem()?;
        name.push(".bootstrap.cache");
        Ok(PathBuf::from(name))
    }

    pub fn read_file(&mut self) -> Vec<PeerInfo> {
        self.file_handler.read_file().ok().unwrap_or_else(|| vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod cache {
        use super::*;

        mod read_file {
            use super::*;
            use util::write_bootstrap_cache_to_tmp_file;

            #[test]
            fn it_returns_addresses_read_from_json_formatted_file() {
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
                let mut cache = unwrap!(Cache::new(Some(Path::new(&fname))));

                let addrs: Vec<PaAddr> = cache.read_file().iter().map(|peer| peer.addr).collect();

                assert!(addrs.contains(&PaAddr::Tcp(addr!("1.2.3.4:4000"))));
                assert!(addrs.contains(&PaAddr::Utp(addr!("1.2.3.5:5000"))));
            }
        }
    }
}
