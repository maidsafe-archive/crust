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

//! Some common utilities to stay DRY (Don't Repeat Yourself).

use crust::{ConfigFile, Peer, PubConnectionInfo, Service, Uid};
use future_utils::{BoxFuture, FutureExt, thread_future};

use futures::{Future, Stream};
use serde_json;
use std::{fmt, io};
use std::path::PathBuf;
use tokio_core::reactor::Core;
use void::Void;

/// Reads single line from stdin.
fn read_line() -> BoxFuture<String, Void> {
    thread_future(|| {
        let stdin = io::stdin();
        let mut line = String::new();
        unwrap!(stdin.read_line(&mut line));
        line
    }).into_boxed()
}

// Some peer ID boilerplate.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Rand)]
pub struct PeerId(u64);

impl Uid for PeerId {}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let PeerId(ref id) = *self;
        write!(f, "{:x}", id)
    }
}

/// Starts accepting peer connections and connects itself to a given peer.
/// After successful connection peer is returned.
pub fn connect_to_peer(event_loop: &mut Core, service_id: PeerId) -> Peer<PeerId> {
    let config =
        unwrap!(
        ConfigFile::open_path(PathBuf::from("sample.config")),
        "Failed to read crust config file: sample.config",
    );
    let make_service = Service::with_config(&event_loop.handle(), config, service_id);
    let service =
        unwrap!(
        event_loop.run(make_service),
        "Failed to create Service object",
    );

    let listeners =
        unwrap!(
        event_loop.run(service.start_listening().collect()),
        "Failed to start listening to peers",
    );
    for listener in &listeners {
        println!("Listening on {}", listener.addr());
    }

    let our_conn_info =
        unwrap!(
        event_loop.run(service.prepare_connection_info()),
        "Failed to prepare connection info",
    );
    let pub_conn_info = our_conn_info.to_pub_connection_info();
    println!(
        "Public connection information:\n{}\n",
        unwrap!(serde_json::to_string(&pub_conn_info))
    );

    println!("Enter remote peer public connection info:");
    let connect = read_line().infallible().and_then(move |ln| {
        let their_info: PubConnectionInfo<PeerId> = unwrap!(serde_json::from_str(&ln));
        service.connect(our_conn_info, their_info)
    });
    unwrap!(event_loop.run(connect))
}
