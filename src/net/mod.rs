// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub use self::listener::{Acceptor, Listener};
pub use self::peer::{
    bootstrap, BootstrapAcceptError, BootstrapAcceptor, BootstrapCache, BootstrapCacheError,
    BootstrapError, ConnectError, ConnectHandshakeError, Demux, ExternalReachability,
    P2pConnectionInfo, Peer, PeerError, PrivConnectionInfo, PubConnectionInfo,
    RendezvousConnectError, SingleConnectionError,
};
pub use self::protocol_agnostic::{
    DirectConnectError, PaAddr, PaIncoming, PaListener, PaRendezvousConnectError, PaStream,
    PaStreamReadError, PaStreamWriteError, PaTcpAddrQuerier, PaUdpAddrQuerier,
    UtpRendezvousConnectError,
};
pub use self::service_discovery::ServiceDiscovery;
//pub use self::socket::{Priority, Socket, SocketError, MAX_PAYLOAD_SIZE};

#[macro_use]
mod protocol_agnostic;
mod listener;
pub mod peer;
pub mod service_discovery;
//mod socket;
