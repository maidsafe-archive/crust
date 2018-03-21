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

use compat::{CrustEventSender, Event};
use future_utils::{self, DropNotify};
use futures::stream::SplitSink;
use log::LogLevel;
use priv_prelude::*;
use std::sync::{Arc, Mutex};

/// Reference counted connection hashmap.
#[derive(Clone)]
pub struct ConnectionMap<UID: Uid> {
    inner: Arc<Mutex<Inner<UID>>>,
}

struct Inner<UID: Uid> {
    map: HashMap<UID, PeerWrapper<UID>>,
    event_tx: CrustEventSender<UID>,
}

struct PeerWrapper<UID: Uid> {
    _drop_tx: DropNotify,
    addr: PaAddr,
    kind: CrustUser,
    peer_sink: SplitSink<Peer<UID>>,
}

impl<UID: Uid> ConnectionMap<UID> {
    /// Creates new peer connection hashmap that is able to fire events when:
    /// * new messages arrive to peers;
    /// * peer connection is lost.
    pub fn new(event_tx: CrustEventSender<UID>) -> ConnectionMap<UID> {
        let inner = Inner {
            map: HashMap::new(),
            event_tx: event_tx,
        };
        let inner = Arc::new(Mutex::new(inner));
        ConnectionMap { inner }
    }

    /// Insert new peer into the map and registers peer event handlers.
    pub fn insert_peer(&self, handle: &Handle, peer: Peer<UID>, addr: PaAddr) -> bool {
        let cm = self.clone();
        let (drop_tx, drop_rx) = future_utils::drop_notify();
        let uid = peer.uid();
        let kind = peer.kind();
        let (peer_sink, peer_stream) = peer.split();

        let mut inner = unwrap!(self.inner.lock());
        if inner.map.contains_key(&uid) {
            return false;
        }

        let event_tx0 = inner.event_tx.clone();
        let event_tx1 = inner.event_tx.clone();
        handle.spawn({
            peer_stream
                .log_errors(LogLevel::Info, "receiving data from peer")
                .until(drop_rx)
                .for_each(move |msg| {
                    let _ = event_tx0.send(Event::NewMessage(uid, kind, msg));
                    Ok(())
                })
                .finally(move || {
                    let _ = cm.remove(&uid);
                    let _ = event_tx1.send(Event::LostPeer(uid));
                })
                .infallible()
        });

        let pw = PeerWrapper {
            _drop_tx: drop_tx,
            addr,
            kind,
            peer_sink,
        };

        let _ = inner.map.insert(uid, pw);
        true
    }

    /// Sends a message to a given peer.
    /// If peer is not found in the hashmap, error is returned.
    pub fn send(&self, uid: &UID, msg: Vec<u8>, priority: Priority) -> Result<(), CrustError> {
        let mut inner = unwrap!(self.inner.lock());
        let peer = match inner.map.get_mut(uid) {
            Some(peer) => peer,
            None => return Err(CrustError::PeerNotFound),
        };
        match peer.peer_sink.start_send((priority, msg))? {
            AsyncSink::NotReady(..) => unreachable!(),
            AsyncSink::Ready => (),
        };
        Ok(())
    }

    /// Returns peer socket address or error, if peer is not found.
    pub fn peer_addr(&self, uid: &UID) -> Result<PaAddr, CrustError> {
        let inner = unwrap!(self.inner.lock());
        inner
            .map
            .get(uid)
            .map(|pw| Ok(pw.addr))
            .unwrap_or(Err(CrustError::PeerNotFound))
    }

    /// Remove peer from the hashmap by id.
    pub fn remove(&self, uid: &UID) -> bool {
        let mut inner = unwrap!(self.inner.lock());
        inner.map.remove(uid).is_some()
    }

    /// Checks if peer with given id exists in the hashmap.
    pub fn contains_peer(&self, uid: &UID) -> bool {
        let inner = unwrap!(self.inner.lock());
        inner.map.contains_key(uid)
    }

    /// Filters out peers with given IP addresses.
    pub fn whitelist_filter(&self, client_ips: &HashSet<IpAddr>, node_ips: &HashSet<IpAddr>) {
        let mut inner = unwrap!(self.inner.lock());
        inner.map.retain(|_, pw| match pw.kind {
            CrustUser::Node => node_ips.contains(&pw.addr.ip()),
            CrustUser::Client => client_ips.contains(&pw.addr.ip()),
        })
    }

    /// Clears the connection hashmap.
    pub fn clear(&self) {
        let mut inner = unwrap!(self.inner.lock());
        inner.map.clear();
    }
}
