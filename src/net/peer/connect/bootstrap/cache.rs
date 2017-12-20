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

use config_file_handler::{self, FileHandler};
use priv_prelude::*;

pub struct Cache {
    file_handler: FileHandler<Vec<PaAddr>>,
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

    pub fn read_file(&mut self) -> Vec<PaAddr> {
        self.file_handler.read_file().ok().unwrap_or_else(|| vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_file_handler::current_bin_dir;
    use rand;
    use std::fs::File;
    use std::io::Write;

    fn write_json_to_tmp_file(content: &[u8]) -> String {
        let mut path = unwrap!(current_bin_dir());
        let fname = format!("{:08x}.bootstrap.cache", rand::random::<u64>());
        path.push(fname.clone());

        let mut f = unwrap!(File::create(path));
        unwrap!(f.write_all(content));
        fname
    }

    mod cache {
        use super::*;

        mod read_file {
            use super::*;

            #[test]
            fn it_returns_addresses_read_from_json_formatted_file() {
                let fname =
                    write_json_to_tmp_file(b"[\"tcp://1.2.3.4:4000\", \"utp://1.2.3.5:5000\"]");
                let mut cache = unwrap!(Cache::new(Some(Path::new(&fname))));

                let addrs = cache.read_file();

                assert!(addrs.contains(&PaAddr::Tcp(addr!("1.2.3.4:4000"))));
                assert!(addrs.contains(&PaAddr::Utp(addr!("1.2.3.5:5000"))));
            }
        }
    }
}
