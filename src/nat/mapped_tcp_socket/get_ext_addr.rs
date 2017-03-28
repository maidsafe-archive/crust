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

use common::{Core, Message, Priority, Socket, State};
use mio::{Poll, PollOpt, Ready, Token};
use mio::tcp::TcpStream;
use nat::{NatError, util};
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;

pub type Finish = Box<FnMut(&mut Core, &Poll, Token, Result<SocketAddr, ()>)>;

pub struct GetExtAddr {
    token: Token,
    socket: Socket,
    request: Option<(Message, Priority)>,
    finish: Finish,
}

impl GetExtAddr {
    pub fn start(core: &mut Core,
                 poll: &Poll,
                 local_addr: SocketAddr,
                 peer_stun: &SocketAddr,
                 finish: Finish)
                 -> Result<Token, NatError> {
        let query_socket = util::new_reusably_bound_tcp_socket(&local_addr)?;
        let query_socket = query_socket.to_tcp_stream()?;
        let socket = TcpStream::connect_stream(query_socket, peer_stun)?;

        let socket = Socket::wrap(socket);
        let token = core.get_new_token();

        let state = GetExtAddr {
            token: token,
            socket: socket,
            request: Some((Message::EchoAddrReq, 0)),
            finish: finish,
        };

        poll.register(&state.socket,
                      token,
                      Ready::error() | Ready::hup() | Ready::writable(),
                      PollOpt::edge())?;

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(token)
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, msg: Option<(Message, Priority)>) {
        if self.socket.write(poll, self.token, msg).is_err() {
            self.handle_error(core, poll);
        }
    }

    fn receive_response(&mut self, core: &mut Core, poll: &Poll) {
        match self.socket.read::<Message>() {
            Ok(Some(Message::EchoAddrResp(ext_addr))) => {
                self.terminate(core, poll);
                let token = self.token;
                (*self.finish)(core, poll, token, Ok(ext_addr))
            }
            Ok(None) => (),
            Ok(Some(_)) | Err(_) => self.handle_error(core, poll),
        }
    }

    fn handle_error(&mut self, core: &mut Core, poll: &Poll) {
        self.terminate(core, poll);
        let token = self.token;
        (*self.finish)(core, poll, token, Err(()));
    }
}

impl State for GetExtAddr {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_error() || kind.is_hup() {
            self.handle_error(core, poll);
        } else {
            if kind.is_writable() {
                let req = self.request.take();
                self.write(core, poll, req);
            }
            if kind.is_readable() {
                self.receive_response(core, poll)
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.socket);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
