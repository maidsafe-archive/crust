// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use common::{BootstrapDenyReason, Core, ExternalReachability, Message, NameHash, State, Uid};
use mio::{Poll, PollOpt, Ready, Token};
use socket_collection::{Priority, TcpSock};
use std::any::Any;
use std::cell::RefCell;
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;

pub type Finish<UID> = Box<
    FnMut(
        &mut Core,
        &Poll,
        Token,
        Result<(TcpSock, SocketAddr, UID), (SocketAddr, Option<BootstrapDenyReason>)>,
    ),
>;

pub struct TryPeer<UID: Uid> {
    token: Token,
    peer: SocketAddr,
    socket: TcpSock,
    request: Option<(Message<UID>, Priority)>,
    finish: Finish<UID>,
}

impl<UID: Uid> TryPeer<UID> {
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        peer: SocketAddr,
        our_uid: UID,
        name_hash: NameHash,
        ext_reachability: ExternalReachability,
        finish: Finish<UID>,
    ) -> ::Res<Token> {
        let socket = TcpSock::connect(&peer)?;
        let token = core.get_new_token();

        poll.register(
            &socket,
            token,
            Ready::writable() | Ready::readable(),
            PollOpt::edge(),
        )?;

        let state = TryPeer {
            token,
            peer,
            socket,
            request: Some((
                Message::BootstrapRequest(our_uid, name_hash, ext_reachability),
                0,
            )),
            finish,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(token)
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, msg: Option<(Message<UID>, Priority)>) {
        if self.socket.write(msg).is_err() {
            self.handle_error(core, poll, None);
        }
    }

    fn read(&mut self, core: &mut Core, poll: &Poll) {
        match self.socket.read::<Message<UID>>() {
            Ok(Some(Message::BootstrapGranted(peer_uid))) => {
                let _ = core.remove_state(self.token);
                let token = self.token;
                let socket = mem::replace(&mut self.socket, Default::default());
                let data = (socket, self.peer, peer_uid);
                (*self.finish)(core, poll, token, Ok(data));
            }
            Ok(Some(Message::BootstrapDenied(reason))) => {
                self.handle_error(core, poll, Some(reason))
            }
            Ok(None) => (),
            Ok(Some(_)) | Err(_) => self.handle_error(core, poll, None),
        }
    }

    fn handle_error(&mut self, core: &mut Core, poll: &Poll, reason: Option<BootstrapDenyReason>) {
        self.terminate(core, poll);
        let token = self.token;
        let peer = self.peer;
        (*self.finish)(core, poll, token, Err((peer, reason)));
    }
}

impl<UID: Uid> State for TryPeer<UID> {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_writable() || kind.is_readable() {
            if kind.is_writable() {
                let req = self.request.take();
                self.write(core, poll, req);
            }
            if kind.is_readable() {
                self.read(core, poll)
            }
            return;
        }

        debug!(
            "Considering the following event to indicate dirupted connection: {:?}",
            kind
        );
        self.handle_error(core, poll, None);
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.socket);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
