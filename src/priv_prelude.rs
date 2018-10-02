// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! This module re-exports a bunch of common imports so they can be glob-imported into other
//! modules using `use priv_prelude::*`

pub use bytes::{Bytes, BytesMut};
pub use common::{CrustUser, NameHash, HASH_SIZE};
pub use config::ConfigFile;
pub use error::CrustError;
pub use future_utils::{BoxFuture, BoxStream, FutureExt, IoFuture, IoStream, StreamExt, Timeout};
pub use futures::{future, stream, Async, AsyncSink, Future, IntoFuture, Sink, Stream};
pub use log::LogLevel;
pub use maidsafe_utilities::serialisation::{self, SerialisationError};
#[cfg(feature = "connections_info")]
pub use net::peer::ConnectionResult;
pub use net::{
    BootstrapAcceptError, BootstrapCache, BootstrapCacheError, BootstrapError, ConnectError,
    ConnectHandshakeError, ExternalReachability, P2pConnectionInfo, PaRendezvousConnectError, Peer,
    PeerError, PrivConnectionInfo, PubConnectionInfo, RendezvousConnectError,
    SingleConnectionError, UtpRendezvousConnectError,
};
pub use net::{
    DirectConnectError, PaAddr, PaIncoming, PaListener, PaStream, PaStreamReadError,
    PaStreamWriteError, PaTcpAddrQuerier, PaUdpAddrQuerier,
};
pub use net2::TcpBuilder;
pub use p2p::{
    ConnectReusableError, P2p, SocketAddrExt, TcpAddrQuerier, TcpListenerExt,
    TcpRendezvousConnectError, TcpStreamExt, UdpAddrQuerier, UdpRendezvousConnectError,
    UdpSocketExt,
};
pub use safe_crypto::{
    gen_encrypt_keypair, Error as EncryptionError, PublicEncryptKey, SecretEncryptKey,
    SharedSecretKey,
};
pub use serde::de::DeserializeOwned;
pub use serde::Serialize;
pub use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
pub use std::ffi::{OsStr, OsString};
pub use std::marker::PhantomData;
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
pub use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
pub use std::path::{Path, PathBuf};
pub use std::time::{Duration, Instant};
pub use std::{fmt, io, mem};
pub use tokio_core::net::{TcpListener, TcpStream, UdpSocket};
pub use tokio_core::reactor::Handle;
pub use tokio_io::codec::length_delimited::Framed;
pub use tokio_io::{AsyncRead, AsyncWrite};
pub use tokio_utp::{UtpListener, UtpSocket, UtpStream};
#[cfg(test)]
pub use util::memstream;
pub use void::{ResultVoidExt, Void};
