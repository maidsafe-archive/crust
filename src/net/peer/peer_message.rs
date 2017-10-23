#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PeerMessage {
    Heartbeat,
    Data(Vec<u8>),
}

