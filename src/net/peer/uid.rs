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

use std::fmt;
use rust_sodium::crypto::box_::{PublicKey, SecretKey, gen_keypair};

/// Peer unique identifier
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Uid(pub PublicKey);

impl Uid {
    /// Create a new Uid struct from a PublicKey
    pub fn new(pkey: PublicKey) -> Uid {
        Uid(pkey)
    }

    /// Generate a Uid and a SecretKey
    pub fn generate() -> (Uid, SecretKey) {
        let (pkey, skey) = gen_keypair();
        (Uid(pkey), skey)
    }

    /// Returns the public key of the Uid struct
    pub fn pkey(&self) -> PublicKey {
        self.0
    }
}

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut hex: String = String::new();
        
        self.pkey().0
            .iter()
            .for_each(|b| hex.push_str(&format!("{:x}", *b)));

        write!(f, "{}", hex)
    }
}