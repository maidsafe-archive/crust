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

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use connection_states::active_connection::ActiveConnection;
use core::{Core, Context};
use mio::{PollOpt, Token, EventLoop, EventSet};
use mio::tcp::TcpStream;
use peer_id::PeerId;
use state::State;

pub struct EstablishConnection {
    cm: Arc<Mutex<HashMap<PeerId, Context>>>,
    context: Context,
    routing_tx: ::CrustEventSender,
    socket: Option<TcpStream>, // Allows moving out without needing to clone the stream
}

impl EstablishConnection {
    pub fn new(core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               cm: Arc<Mutex<HashMap<PeerId, Context>>>,
               routing_tx: ::CrustEventSender,
               peer_contact_info: SocketAddr) {
        println!("Entered state EstablishConnection");

        let context = core.get_new_context();
        let socket = TcpStream::connect(&peer_contact_info).expect("Could not connect to peer");
        let connection = EstablishConnection {
            cm: cm,
            context: context.clone(),
            routing_tx: routing_tx,
            socket: Some(socket),
        };

        let token = core.get_new_token();
        event_loop.register(connection.socket.as_ref().expect("Logic Error"),
                            token,
                            EventSet::error() | EventSet::writable(),
                            PollOpt::edge())
                  .expect("Could not register socket with EventLoop<Core>");

        let _ = core.insert_context(token, context.clone());
        let _ = core.insert_state(context, Rc::new(RefCell::new(connection)));
    }
}

impl State for EstablishConnection {
    fn execute(&mut self,
               core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               token: Token,
               event_set: EventSet) {
        if event_set.is_error() {
            panic!("connection error");
            // let _ = routing_tx.send(Error - Could not connect);
        } else {
            let context = core.remove_context(&token).expect("Context not found");
            let _ = core.remove_state(&context).expect("State not found");

            println!("EstablishConnection successful -> Moving to next state ...");
            ActiveConnection::new(core,
                                  event_loop,
                                  self.cm.clone(),
                                  self.context.clone(),
                                  self.socket.take().expect("Logic Error"),
                                  self.routing_tx.clone());
        }
    }
}
