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

//! Utilities for use in tests. This module is only available when running with cfg(test)

use config_file_handler::current_bin_dir;
use priv_prelude::*;
use rand::{self, Rng};
use std::env;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Rand)]
pub struct UniqueId(pub [u8; 20]);
impl Uid for UniqueId {}

impl fmt::Display for UniqueId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let UniqueId(ref id) = *self;
        for byte in id {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

pub fn random_id() -> UniqueId {
    rand::thread_rng().gen()
}

#[allow(unsafe_code)]
pub fn random_vec(size: usize) -> Vec<u8> {
    let mut ret = Vec::with_capacity(size);
    unsafe { ret.set_len(size) };
    rand::thread_rng().fill_bytes(&mut ret[..]);
    ret
}

/// # Arguments
///
/// * `content` - json formatted bootstrap cache to be written to file.
///
/// # Returns
///
/// file name where content was written to.
pub fn write_bootstrap_cache_to_tmp_file(content: &[u8]) -> OsString {
    let mut path = unwrap!(current_bin_dir());
    let fname = format!("{:08x}.bootstrap.cache", rand::random::<u64>());
    path.push(fname.clone());

    let mut f = unwrap!(File::create(path));
    unwrap!(f.write_all(content));
    fname.into()
}

/// Constructs random bootstrap cache file name.
pub fn bootstrap_cache_tmp_file() -> OsString {
    let file_name = format!("{:016x}.bootstrap.cache", rand::random::<u64>());
    let mut path = env::temp_dir();
    path.push(file_name);
    path.into()
}
