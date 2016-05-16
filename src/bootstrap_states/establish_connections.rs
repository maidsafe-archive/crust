// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use mio::EventLoop;

use connection_states::EstablishConnection;
use core::{Core, State, StateHandle};
use core::channel::{self, Receiver};
use error::Error;
use event::Event;
use peer_id::PeerId;
use service::SharedConnectionMap;
use static_contact_info::StaticContactInfo;

pub struct EstablishBootstrapConnections {
    handle: StateHandle,
    connection_map: SharedConnectionMap,
    connect_rx: Receiver<(StateHandle, Option<PeerId>)>,
    event_tx: ::CrustEventSender,
    pending_connections: Vec<StateHandle>,
}

impl EstablishBootstrapConnections {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 handle: StateHandle,
                 connection_map: SharedConnectionMap,
                 event_tx: ::CrustEventSender,
                 contacts: Vec<StaticContactInfo>) -> Result<(), Error> {
        let mut connections = Vec::with_capacity(contacts.len());
        let (connect_tx, connect_rx) = channel::new(event_loop, handle);

        for contact in contacts {
            connections.push(try!(EstablishConnection::start(core,
                                                             event_loop,
                                                             contact,
                                                             connect_tx.clone(),
                                                             event_tx.clone())));
        }

        let state = EstablishBootstrapConnections {
            connection_map: connection_map,
            connect_rx: connect_rx,
            event_tx: event_tx,
            pending_connections: connections,
            handle: handle,
        };

        let _ = core.insert_state(handle, state);

        Ok(())
    }

    fn handle_connect_success(&mut self,
                              core: &mut Core,
                              handle: StateHandle,
                              peer_id: PeerId) {
        // TODO: what if the peer id already exists?
        let _ = self.connection_map.lock().unwrap().insert(peer_id, handle);
        let _ = self.event_tx.send(Event::BootstrapConnect(peer_id));
        self.remove_pending_connection(core, handle);
    }

    fn handle_connect_failure(&mut self,
                              core: &mut Core,
                              handle: StateHandle) {
        self.remove_pending_connection(core, handle);
    }

    fn remove_pending_connection(&mut self, core: &mut Core, handle: StateHandle) {
        if let Some(index) = self.pending_connections
                                 .iter()
                                 .position(|&h| h == handle) {
            let _ = self.pending_connections.remove(index);
        } else {
            return;
        }

        // All contact exhausted - bootstrap is finished.
        if self.pending_connections.is_empty() {
            let _ = self.event_tx.send(Event::BootstrapFinished);
            let _ = core.remove_state(&self.handle);

            info!("Bootstrap finished");
        }
    }
}

impl State for EstablishBootstrapConnections {
    fn notify(&mut self, core: &mut Core, _: &mut EventLoop<Core>) {
        if let Ok((handle, peer_id)) = self.connect_rx.try_recv() {
            if let Some(peer_id) = peer_id {
                self.handle_connect_success(core, handle, peer_id);
            } else {
                self.handle_connect_failure(core, handle);
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        for handle in self.pending_connections.drain(..) {
            if let Some(state) = core.get_state(&handle) {
                state.borrow_mut().terminate(core, event_loop);
            }
        }
    }
}
