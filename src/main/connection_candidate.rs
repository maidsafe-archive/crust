// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::{Message, State, Uid};
use crate::main::bootstrap::Cache as BootstrapCache;
use crate::main::{ConnectionId, ConnectionMap, EventLoopCore};
use mio::{Poll, PollOpt, Ready, Token};
use socket_collection::{Priority, TcpSock};
use std::any::Any;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::mem;
use std::rc::Rc;

pub type Finish = Box<FnMut(&mut EventLoopCore, &Poll, Token, Option<TcpSock>)>;

/// Exchanges `ConnectionChoose` message with remote peer and transitions to next state.
pub struct ConnectionCandidate<UID: Uid> {
    token: Token,
    cm: ConnectionMap<UID>,
    socket: TcpSock,
    our_id: UID,
    their_id: UID,
    msg: Option<(Message<UID>, Priority)>,
    finish: Finish,
}

impl<UID: Uid> ConnectionCandidate<UID> {
    pub fn start(
        core: &mut EventLoopCore,
        poll: &Poll,
        token: Token,
        socket: TcpSock,
        cm: ConnectionMap<UID>,
        our_id: UID,
        their_id: UID,
        finish: Finish,
    ) -> crate::Res<Token> {
        let state = Rc::new(RefCell::new(ConnectionCandidate {
            token,
            cm,
            socket,
            our_id,
            their_id,
            msg: Some((Message::ChooseConnection, 0)),
            finish,
        }));

        let _ = core.insert_state(token, state.clone());

        if let Err(e) = poll.reregister(
            &state.borrow().socket,
            token,
            Ready::writable(),
            PollOpt::edge(),
        ) {
            state.borrow_mut().terminate(core, poll);
            return Err(From::from(e));
        }

        Ok(token)
    }

    fn read(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        match self.socket.read::<Message<UID>>() {
            Ok(Some(Message::ChooseConnection)) => self.done(core, poll),
            Ok(Some(_)) | Err(_) => self.handle_error(core, poll),
            Ok(None) => (),
        }
    }

    fn write(
        &mut self,
        core: &mut EventLoopCore,
        poll: &Poll,
        msg: Option<(Message<UID>, Priority)>,
    ) {
        let terminate = match unwrap!(self.cm.lock()).get(&self.their_id) {
            Some(&ConnectionId {
                active_connection: Some(_),
                ..
            }) => true,
            _ => false,
        };
        if terminate {
            return self.handle_error(core, poll);
        }

        if self.our_id > self.their_id {
            match self.socket.write(msg) {
                Ok(true) => self.done(core, poll),
                Ok(false) => (),
                Err(_) => self.handle_error(core, poll),
            }
        } else if let Err(e) =
            poll.reregister(&self.socket, self.token, Ready::readable(), PollOpt::edge())
        {
            debug!("Error in re-registeration: {:?}", e);
            self.handle_error(core, poll);
        } else {
            self.read(core, poll)
        }
    }

    fn done(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        let _ = core.remove_state(self.token);
        let token = self.token;
        let socket = mem::replace(&mut self.socket, Default::default());
        let _ = poll.reregister(&socket, token, Ready::readable(), PollOpt::edge());

        (*self.finish)(core, poll, token, Some(socket));
    }

    fn handle_error(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        self.terminate(core, poll);
        let token = self.token;
        (*self.finish)(core, poll, token, None);
    }
}

impl<UID: Uid> State<BootstrapCache> for ConnectionCandidate<UID> {
    fn ready(&mut self, core: &mut EventLoopCore, poll: &Poll, kind: Ready) {
        if kind.is_readable() {
            self.read(core, poll);
        }
        if kind.is_writable() {
            let msg = self.msg.take();
            self.write(core, poll, msg);
        }
    }

    fn terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.socket);

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
