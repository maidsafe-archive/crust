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

use compat::{CompatPeer, CrustEventSender, Event, Priority};
use future_utils::bi_channel::UnboundedBiChannel;
use future_utils::{self, DropNotice, DropNotify};
use futures::stream::{SplitSink, SplitStream};
use log::LogLevel;
use priv_prelude::*;
use std::sync::{Arc, Mutex};

/// Reference counted connection hashmap.
#[derive(Clone)]
pub struct ConnectionMap {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    map: HashMap<PublicId, PeerWrapper>,
    ci_channel: HashMap<u64, UnboundedBiChannel<PubConnectionInfo>>,
    event_tx: CrustEventSender,
}

struct PeerWrapper {
    _drop_tx: DropNotify,
    addr: PaAddr,
    kind: CrustUser,
    peer_sink: SplitSink<CompatPeer>,
}

impl ConnectionMap {
    /// Creates new peer connection hashmap that is able to fire events when:
    /// * new messages arrive to peers;
    /// * peer connection is lost.
    pub fn new(event_tx: CrustEventSender) -> ConnectionMap {
        let inner = Inner {
            map: HashMap::new(),
            ci_channel: HashMap::new(),
            event_tx,
        };
        let inner = Arc::new(Mutex::new(inner));
        ConnectionMap { inner }
    }

    /// Insert new peer into the map and registers peer event handlers.
    pub fn insert_peer(&self, handle: &Handle, peer: CompatPeer, addr: PaAddr) -> bool {
        let (drop_tx, drop_rx) = future_utils::drop_notify();
        let uid = peer.public_id();
        let kind = peer.kind();
        let (peer_sink, peer_stream) = peer.split();

        let mut inner = unwrap!(self.inner.lock());
        if inner.map.contains_key(&uid) {
            return false;
        }

        handle.spawn(handle_peer_rx(
            peer_stream,
            &uid,
            &inner.event_tx,
            drop_rx,
            kind,
            self.clone(),
        ));

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
    pub fn send(&self, uid: &PublicId, msg: Vec<u8>, priority: Priority) -> Result<(), CrustError> {
        let mut inner = unwrap!(self.inner.lock());
        let peer = match inner.map.get_mut(uid) {
            Some(peer) => peer,
            None => return Err(CrustError::PeerNotFound),
        };
        let msg = Bytes::from(msg);
        match peer
            .peer_sink
            .start_send((priority, msg))
            .map_err(|e| CrustError::CompatPeerError(e.to_string()))?
        {
            AsyncSink::NotReady(..) => unreachable!(),
            AsyncSink::Ready => (),
        };
        Ok(())
    }

    /// Returns peer socket address or error, if peer is not found.
    pub fn peer_addr(&self, uid: &PublicId) -> Result<PaAddr, CrustError> {
        let inner = unwrap!(self.inner.lock());
        inner
            .map
            .get(uid)
            .map(|pw| Ok(pw.addr))
            .unwrap_or(Err(CrustError::PeerNotFound))
    }

    /// Remove peer from the hashmap by id.
    pub fn remove(&self, uid: &PublicId) -> bool {
        let mut inner = unwrap!(self.inner.lock());
        inner.map.remove(uid).is_some()
    }

    /// Checks if peer with given id exists in the hashmap.
    pub fn contains_peer(&self, uid: &PublicId) -> bool {
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

    /// Store connection information channel associated with connection ID.
    /// This channel is used to transfer peer's connection info.
    pub fn insert_ci_channel(
        &mut self,
        conn_id: u64,
        chann: UnboundedBiChannel<PubConnectionInfo>,
    ) {
        let mut inner = unwrap!(self.inner.lock());
        let _ = inner.ci_channel.insert(conn_id, chann);
    }

    /// Retrieves connection info channel by connection ID.
    /// The channel is permanently removed from the connection map after this operation.
    pub fn get_ci_channel(
        &mut self,
        conn_id: u64,
    ) -> Option<UnboundedBiChannel<PubConnectionInfo>> {
        let mut inner = unwrap!(self.inner.lock());
        inner.ci_channel.remove(&conn_id)
    }
}

/// Wait for incoming peer data and transform it to appropriate compatibility layer events.
fn handle_peer_rx(
    peer_stream: SplitStream<CompatPeer>,
    uid: &PublicId,
    event_tx: &CrustEventSender,
    drop_rx: DropNotice,
    kind: CrustUser,
    cm: ConnectionMap,
) -> impl Future<Item = (), Error = ()> {
    let event_tx0 = event_tx.clone();
    let event_tx1 = event_tx.clone();
    let uid1 = uid.clone();
    let uid2 = uid.clone();
    peer_stream
        .log_errors(LogLevel::Info, "receiving data from peer")
        .until(drop_rx)
        .for_each(move |msg| {
            let vec = Vec::from(&msg[..]);
            let _ = event_tx0.send(Event::NewMessage(uid1.clone(), kind, vec));
            Ok(())
        })
        .finally(move || {
            let _ = cm.remove(&uid2);
            let _ = event_tx1.send(Event::LostPeer(uid2));
        })
        .infallible()
}

#[cfg(test)]
mod tests {
    use super::*;
    use util::crust_event_channel;

    mod handle_peer_rx {
        use super::*;
        use net::peer;
        use tokio_core::reactor::{Core, Handle};
        use tokio_io::codec::length_delimited::Framed;

        /// Constructs peer with in-memory stream for testing.
        fn echo_peer(handle: &Handle) -> CompatPeer {
            let our_sk = SecretId::new();
            let peer_uid = SecretId::new().public_id().clone();
            let shared_secret = our_sk.shared_secret(&peer_uid);
            let mem_stream = Framed::new(memstream::EchoStream::default());
            let fake_stream = PaStream::from_framed_mem_stream(mem_stream, shared_secret);
            let peer = peer::from_handshaken_stream(
                &handle,
                peer_uid.clone(),
                fake_stream,
                CrustUser::Client,
            );
            CompatPeer::wrap_peer(&handle, peer, peer_uid.clone(), tcp_addr!("0.0.0.0:0"))
        }

        #[test]
        fn it_emits_message_events_for_received_data() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();

            let peer = echo_peer(&handle);
            let peer_uid = peer.public_id();
            let (peer_sink, peer_stream) = peer.split();
            let (_rop_tx, drop_rx) = future_utils::drop_notify();
            let (event_tx, event_rx) = crust_event_channel();
            let conn_map = ConnectionMap::new(event_tx.clone());

            handle.spawn(handle_peer_rx(
                peer_stream,
                &peer_uid,
                &event_tx,
                drop_rx,
                CrustUser::Client,
                conn_map,
            ));
            let send_data = peer_sink.send((1, Bytes::from(&b"data1"[..])));
            let _ = unwrap!(evloop.run(send_data));
            // run event loop so that messages would get transfered
            unwrap!(evloop.run(Timeout::new(Duration::from_secs(2), &handle)));

            let msg = unwrap!(event_rx.recv());
            match msg {
                Event::NewMessage(_, _, data) => {
                    assert_eq!(data.len(), 5);
                    assert_eq!(&data[..5], &b"data1"[..5]);
                }
                event => panic!("Unexpected event: {:?}", event),
            }
        }
    }
}
