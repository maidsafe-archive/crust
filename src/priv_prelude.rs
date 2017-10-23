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

pub use std::{io, mem, fmt};
pub use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
pub use std::marker::PhantomData;
pub use std::collections::{HashMap, HashSet, BTreeMap, BTreeSet, VecDeque};
pub use std::path::{Path, PathBuf};
pub use std::time::{Duration, Instant};
pub use futures::{future, stream, Async, AsyncSink, Future, Stream, Sink, IntoFuture};
pub use future_utils::{FutureExt, StreamExt, BoxFuture, BoxStream, IoFuture, IoStream};
pub use tokio_core::reactor::Handle;
pub use tokio_core::net::{TcpStream, TcpListener};
pub use serde::Serialize;
pub use serde::de::DeserializeOwned;
pub use net2::TcpBuilder;
pub use void::{Void, ResultVoidExt};

pub use net::Uid;
pub use config::ConfigFile;
pub use error::CrustError;
pub use net::{PeerError, ConnectHandshakeError, BootstrapAcceptError, BootstrapError, ExternalReachability, NatError, MappingContext, Peer, PrivConnectionInfo, PubConnectionInfo, Socket, SocketError, ConnectError, Priority, StunError};
pub use common::{CrustUser, NameHash, HASH_SIZE};
pub use util::{FutureExt as UtilFutureExt, Timeout};

