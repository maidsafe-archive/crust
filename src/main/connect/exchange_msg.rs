// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use common::{Core, Message, NameHash, Priority, Socket, State, Uid};
use main::{ConnectionId, ConnectionMap};
use mio::{Poll, PollOpt, Ready, Token};
use std::any::Any;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::mem;
use std::rc::Rc;

pub type Finish = Box<FnMut(&mut Core, &Poll, Token, Option<Socket>)>;

pub struct ExchangeMsg<UID: Uid> {
    token: Token,
    expected_id: UID,
    expected_nh: NameHash,
    socket: Socket,
    cm: ConnectionMap<UID>,
    msg: Option<(Message<UID>, Priority)>,
    finish: Finish,
}

impl<UID: Uid> ExchangeMsg<UID> {
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        socket: Socket,
        our_id: UID,
        expected_id: UID,
        name_hash: NameHash,
        cm: ConnectionMap<UID>,
        finish: Finish,
    ) -> ::Res<Token> {
        let token = core.get_new_token();

        poll.register(&socket, token, Ready::writable(), PollOpt::edge())?;

        {
            let mut guard = unwrap!(cm.lock());
            guard
                .entry(expected_id)
                .or_insert(ConnectionId {
                    active_connection: None,
                    currently_handshaking: 0,
                }).currently_handshaking += 1;
            trace!(
                "Connection Map inserted: {:?} -> {:?}",
                expected_id,
                guard.get(&expected_id)
            );
        }

        let state = Self {
            token,
            expected_id,
            expected_nh: name_hash,
            socket,
            cm,
            msg: Some((Message::Connect(our_id, name_hash), 0)),
            finish,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(token)
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, msg: Option<(Message<UID>, Priority)>) {
        if self.socket.write(poll, self.token, msg).is_err() {
            self.handle_error(core, poll);
        }
    }

    fn receive_response(&mut self, core: &mut Core, poll: &Poll) {
        match self.socket.read::<Message<UID>>() {
            Ok(Some(Message::Connect(their_uid, name_hash))) => {
                if their_uid != self.expected_id || name_hash != self.expected_nh {
                    return self.handle_error(core, poll);
                }
                let _ = core.remove_state(self.token);
                let token = self.token;
                let socket = mem::replace(&mut self.socket, Socket::default());

                (*self.finish)(core, poll, token, Some(socket));
            }
            Ok(None) => (),
            Ok(Some(_)) | Err(_) => self.handle_error(core, poll),
        }
    }

    fn handle_error(&mut self, core: &mut Core, poll: &Poll) {
        self.terminate(core, poll);
        let token = self.token;
        (*self.finish)(core, poll, token, None);
    }
}

impl<UID: Uid> State for ExchangeMsg<UID> {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_writable() {
            let req = self.msg.take();
            self.write(core, poll, req);
        }
        if kind.is_readable() {
            self.receive_response(core, poll)
        }
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.socket);

        let mut guard = unwrap!(self.cm.lock());
        if let Entry::Occupied(mut oe) = guard.entry(self.expected_id) {
            oe.get_mut().currently_handshaking -= 1;
            if oe.get().currently_handshaking == 0 && oe.get().active_connection.is_none() {
                let _ = oe.remove();
            }
        }
        trace!(
            "Connection Map removed: {:?} -> {:?}",
            self.expected_id,
            guard.get(&self.expected_id)
        );
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
