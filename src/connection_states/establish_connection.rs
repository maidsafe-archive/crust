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

use mio::{PollOpt, Token, EventLoop, EventSet};
use mio::tcp::TcpStream;

use super::active_connection::ActiveConnection;
use core::{Core, State, StateHandle};
use core::channel::Sender;
use error::Error;
use peer_id::PeerId;
use static_contact_info::StaticContactInfo;

pub struct EstablishConnection {
    handle: StateHandle,
    socket: Option<TcpStream>, // Allows moving out without needing to clone the stream
    token: Token,
    connect_tx: Sender<(StateHandle, Option<PeerId>)>,
    event_tx: ::CrustEventSender,
}

impl EstablishConnection {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 peer_contact_info: StaticContactInfo,
                 connect_tx: Sender<(StateHandle, Option<PeerId>)>,
                 event_tx: ::CrustEventSender)
        -> Result<StateHandle, Error>
    {
        info!("Entered state EstablishConnection");

        let handle = core.get_new_state_handle();

        // TODO: spin up one socket per each tcp_acceptor
        let socket = try!(TcpStream::connect(&peer_contact_info.tcp_acceptors[0]));
        let token = core.get_new_token();
        let connection = EstablishConnection {
            handle: handle,
            socket: Some(socket),
            token: token,
            connect_tx: connect_tx,
            event_tx: event_tx,
        };

        try!(event_loop.register(connection.socket.as_ref().expect("Logic Error"),
                                 token,
                                 EventSet::error() | EventSet::writable(),
                                 PollOpt::edge()));

        let _ = core.insert_state_handle(token, handle);
        let _ = core.insert_state(handle, connection);

        Ok(handle)
    }
}

impl State for EstablishConnection {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet) {
        if event_set.is_error() {
            let _ = self.connect_tx.send((self.handle, None));
        } else {
            let _ = core.remove_state_by_token(&token).expect("State not found");

            info!("EstablishConnection successful -> Moving to next state ...");
            ActiveConnection::new(core,
                                  event_loop,
                                  self.handle,
                                  self.socket.take().expect("Logic Error"),
                                  self.token,
                                  self.event_tx.clone());
        }
    }

    fn terminate(&mut self, core: &mut Core, _: &mut EventLoop<Core>) {
        let _ = core.remove_state_by_token(&self.token);
    }
}
