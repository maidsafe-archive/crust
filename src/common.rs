/// Specify crust user. Behaviour (for example in bootstrap phase) will be different for different
/// variants. Node will request the Bootstrapee to connect back to this crust failing which it
/// would mean it's not reachable from outside and hence should be rejected bootstrap attempts.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CrustUser {
    /// Crust user is a Node and should not be allowed to bootstrap if it's not reachable from
    /// outside.
    Node,
    /// Crust user is a Client and should be allowed to bootstrap even if it's not reachable from
    /// outside.
    Client,
}

/// The size of a `NameHash`.
pub const HASH_SIZE: usize = 32;

/// Every network that crust can connect to has its own id, identified by a `NameHash`. When
/// connecting to a peer, we check that they are using the same `NameHash` as us.
pub type NameHash = [u8; HASH_SIZE];

