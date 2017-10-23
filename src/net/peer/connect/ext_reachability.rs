use priv_prelude::*;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExternalReachability {
    NotRequired,
    Required { direct_listeners: Vec<SocketAddr> },
}

