use priv_prelude::*;
use std::hash::Hash;

/// A trait for types which can act an an ID
pub trait Uid:
    'static
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
    + DeserializeOwned
{
}
