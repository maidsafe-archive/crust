

use crust::Uid;
use std::fmt;

// Some peer ID boilerplate.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Rand)]
pub struct PeerId(u64);

impl Uid for PeerId {}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let PeerId(ref id) = *self;
        write!(f, "{:x}", id)
    }
}
