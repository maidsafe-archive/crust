// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! This module re-exports a bunch of common imports so they can be glob-imported into other
//! modules using `use priv_prelude::*`


pub use bytes::{Bytes, BytesMut};
pub use common::{CrustUser, HASH_SIZE, NameHash};
pub use config::ConfigFile;
pub use crypto::{CryptoContext, CryptoError};
pub use error::CrustError;
pub use future_utils::{BoxFuture, BoxStream, FutureExt, IoFuture, IoStream, StreamExt, Timeout};
pub use futures::{Async, AsyncSink, Future, IntoFuture, Sink, Stream, future, stream};
pub use net::{BootstrapAcceptError, BootstrapError, ConnectError, ConnectHandshakeError,
              ExternalReachability, P2pConnectionInfo, PaRendezvousConnectError, Peer, PeerError,
              Priority, PrivConnectionInfo, PubConnectionInfo, RendezvousConnectError,
              SingleConnectionError, Socket, SocketError, UtpRendezvousConnectError};
pub use net::{PaAddr, PaIncoming, PaListener, PaStream};
pub use net::Uid;
pub use net2::TcpBuilder;
pub use p2p::{P2p, SocketAddrExt, TcpListenerExt, TcpStreamExt, UdpSocketExt};
pub use p2p::{TcpRendezvousConnectError, UdpRendezvousConnectError};
pub use serde::Serialize;
pub use serde::de::DeserializeOwned;
pub use std::{fmt, io, mem};
pub use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
pub use std::marker::PhantomData;
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
pub use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
pub use std::path::{Path, PathBuf};
pub use std::time::{Duration, Instant};
pub use tokio_core::net::{TcpListener, TcpStream, UdpSocket};
pub use tokio_core::reactor::Handle;
pub use tokio_utp::{UtpListener, UtpSocket, UtpStream};
pub use void::{ResultVoidExt, Void};
