use std::hash::Hash;
use priv_prelude::*;

/// Trait for specifying a unique identifier for a Crust peer
pub trait Uid
    : 'static
    + Send
    + fmt::Debug
    + fmt::Display
    + Clone
    + Copy
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Hash
    + Serialize
    + DeserializeOwned {
}

