use priv_prelude::*;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BootstrapRequest<UID> {
    pub uid: UID,
    pub name_hash: NameHash,
    pub ext_reachability: ExternalReachability,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConnectRequest<UID> {
    pub uid: UID,
    pub name_hash: NameHash,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HandshakeMessage<UID> {
    BootstrapRequest(BootstrapRequest<UID>),
    BootstrapGranted(UID),
    BootstrapDenied(BootstrapDenyReason),
    EchoAddrReq,
    EchoAddrResp(SocketAddr),
    ChooseConnection,
    Connect(ConnectRequest<UID>),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BootstrapDenyReason {
    InvalidNameHash,
    FailedExternalReachability,
    NodeNotWhitelisted,
    ClientNotWhitelisted,
}


