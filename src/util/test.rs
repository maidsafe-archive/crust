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

use priv_prelude::*;

use rand::{self, Rng};

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

pub fn random_vec(size: usize) -> Vec<u8> {
    let mut ret = Vec::with_capacity(size);
    unsafe { ret.set_len(size) };
    rand::thread_rng().fill_bytes(&mut ret[..]);
    ret
}
