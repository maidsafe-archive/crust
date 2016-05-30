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

use mio::{EventLoop, Timeout, Token};
use sodiumoxide::crypto::box_::PublicKey;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::mem;
use std::rc::Rc;

use core::{Context, Core, State};
use event::Event;
use service::SharedConnectionMap;
use static_contact_info::StaticContactInfo;
use super::establish_connection::EstablishConnection;

const BOOTSTRAP_TIMEOUT_MS: u64 = 60_000;

pub struct Bootstrap {
    context: Context,
    event_tx: ::CrustEventSender,
    pending_connections: Rc<RefCell<HashSet<Context>>>,
    timeout: Timeout,
    token: Token,
}

impl Bootstrap {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 context: Context,
                 connection_map: SharedConnectionMap,
                 event_tx: ::CrustEventSender,
                 contacts: Vec<StaticContactInfo>,
                 our_public_key: PublicKey,
                 name_hash: u64) {
        let token = core.get_new_token();
        let timeout = match event_loop.timeout_ms(token, BOOTSTRAP_TIMEOUT_MS) {
            Ok(timeout) => timeout,
            Err(error) => {
                error!("Failed to schedule bootstrap timeout: {:?}", error);
                let _ = event_tx.send(Event::BootstrapFailed);
                return;
            }
        };

        let pending_connections = Rc::new(RefCell::new(HashSet::with_capacity(contacts.len())));

        for contact in contacts {
            EstablishConnection::start(core,
                                       event_loop,
                                       contact,
                                       our_public_key,
                                       name_hash,
                                       pending_connections.clone(),
                                       connection_map.clone(),
                                       context,
                                       event_tx.clone());
        }

        if pending_connections.borrow().is_empty() {
            let _ = event_tx.send(Event::BootstrapFailed);
            return;
        }


        let state = Bootstrap {
            context: context,
            event_tx: event_tx,
            pending_connections: pending_connections,
            timeout: timeout,
            token: token,
        };

        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));
        let _ = core.insert_context(token, context);
    }
}

impl State for Bootstrap {
    fn as_any(&mut self) -> &mut Any {
        self
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let connections = mem::replace(&mut *self.pending_connections.borrow_mut(), HashSet::new());

        for context in connections {
            core.terminate_state(event_loop, context);
        }

        let _ = event_loop.clear_timeout(self.timeout);
        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);
    }

    fn timeout(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, _: Token) {
        let _ = self.event_tx.send(Event::BootstrapFailed);
        self.terminate(core, event_loop);
    }
}
