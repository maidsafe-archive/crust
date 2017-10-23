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
    unsafe {
        ret.set_len(size)
    };
    rand::thread_rng().fill_bytes(&mut ret[..]);
    ret
}

