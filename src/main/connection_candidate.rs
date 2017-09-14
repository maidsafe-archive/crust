// Copyright 2016 MaidSafe.net limited.
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

use common::{Core, FakePoll, Message, Priority, Socket, State, Uid};
use main::{ConnectionId, ConnectionMap};
use mio::{Ready, Token};
use std::any::Any;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::mem;
use std::rc::Rc;

pub type Finish = Box<FnMut(&mut Core, &FakePoll, Token, Option<Socket>)>;

pub struct ConnectionCandidate<UID: Uid> {
    token: Token,
    cm: ConnectionMap<UID>,
    socket: Socket,
    our_id: UID,
    their_id: UID,
    msg: Option<(Message<UID>, Priority)>,
    finish: Finish,
}

impl<UID: Uid> ConnectionCandidate<UID> {
    pub fn start(
        core: &mut Core,
        poll: &FakePoll,
        token: Token,
        socket: Socket,
        cm: ConnectionMap<UID>,
        our_id: UID,
        their_id: UID,
        finish: Finish,
    ) -> ::Res<Token> {
        let state = Rc::new(RefCell::new(ConnectionCandidate {
            token: token,
            cm: cm,
            socket: socket,
            our_id: our_id,
            their_id: their_id,
            msg: Some((Message::ChooseConnection, 0)),
            finish: finish,
        }));

        let _ = core.insert_state(token, state.clone());

        if let Err(e) = poll.reregister(
            &state.borrow().socket,
            token,
            Ready::writable() | Ready::error() | Ready::hup(),
        )
        {
            state.borrow_mut().terminate(core, poll);
            return Err(From::from(e));
        }

        Ok(token)
    }

    fn read(&mut self, core: &mut Core, poll: &FakePoll) {
        match self.socket.read::<Message<UID>>() {
            Ok(Some(Message::ChooseConnection)) => self.done(core, poll),
            Ok(Some(_)) | Err(_) => self.handle_error(core, poll),
            Ok(None) => (),
        }
    }

    fn write(&mut self, core: &mut Core, poll: &FakePoll, msg: Option<(Message<UID>, Priority)>) {
        let terminate = match unwrap!(self.cm.lock()).get(&self.their_id) {
            Some(&ConnectionId { active_connection: Some(_), .. }) => true,
            _ => false,
        };
        if terminate {
            return self.handle_error(core, poll);
        }

        if self.our_id > self.their_id {
            match self.socket.write(poll, self.token, msg) {
                Ok(true) => self.done(core, poll),
                Ok(false) => (),
                Err(_) => self.handle_error(core, poll),
            }
        } else if let Err(e) = poll.reregister(
            &self.socket,
            self.token,
            Ready::readable() | Ready::error() | Ready::hup(),
        )
        {
            debug!("Error in re-registeration: {:?}", e);
            self.handle_error(core, poll);
        } else {
            self.read(core, poll)
        }
    }

    fn done(&mut self, core: &mut Core, poll: &FakePoll) {
        let _ = core.remove_state(self.token);
        let token = self.token;
        let socket = mem::replace(&mut self.socket, Socket::default());

        (*self.finish)(core, poll, token, Some(socket));
    }

    fn handle_error(&mut self, core: &mut Core, poll: &FakePoll) {
        self.terminate(core, poll);
        let token = self.token;
        (*self.finish)(core, poll, token, None);
    }
}

impl<UID: Uid> State for ConnectionCandidate<UID> {
    fn ready(&mut self, core: &mut Core, poll: &FakePoll, kind: Ready) {
        if kind.is_error() || kind.is_hup() {
            return self.handle_error(core, poll);
        }
        if kind.is_readable() {
            self.read(core, poll);
        }
        if kind.is_writable() {
            let msg = self.msg.take();
            self.write(core, poll, msg);
        }
    }

    fn terminate(&mut self, core: &mut Core, poll: &FakePoll) {
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(self.token);

        let mut guard = unwrap!(self.cm.lock());
        if let Entry::Occupied(mut oe) = guard.entry(self.their_id) {
            oe.get_mut().currently_handshaking -= 1;
            if oe.get().currently_handshaking == 0 && oe.get().active_connection.is_none() {
                let _ = oe.remove();
            }
        }
        trace!(
            "Connection Map removed: {:?} -> {:?}",
            self.their_id,
            guard.get(&self.their_id)
        );
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
