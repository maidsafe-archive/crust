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


use common::{Core, Message, Priority, Socket, State};
use mio::{EventLoop, EventSet, PollOpt, Token};
use mio::tcp::TcpStream;
use nat::{NatError, util};
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;

pub type Finish = Box<FnMut(&mut Core,
                            &mut EventLoop<Core>,
                            Token,
                            Result<SocketAddr, ()>)>;

pub struct GetExtAddr {
    token: Token,
    socket: Socket,
    request: Option<(Message, Priority)>,
    finish: Finish,
}

impl GetExtAddr {
    pub fn start(core: &mut Core,
                 el: &mut EventLoop<Core>,
                 local_addr: SocketAddr,
                 peer_stun: &SocketAddr,
                 finish: Finish)
                 -> Result<Token, NatError> {
        let query_socket = try!(util::new_reusably_bound_tcp_socket(&local_addr));
        let query_socket = try!(query_socket.to_tcp_stream());
        let socket = try!(TcpStream::connect_stream(query_socket, peer_stun));

        let socket = Socket::wrap(socket);
        let token = core.get_new_token();

        let state = GetExtAddr {
            token: token,
            socket: socket,
            request: Some((Message::EchoAddrReq, 0)),
            finish: finish,
        };

        try!(el.register(&state.socket,
                         token,
                         EventSet::error() | EventSet::hup() | EventSet::writable(),
                         PollOpt::edge()));

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(token)
    }

    fn write(&mut self,
             core: &mut Core,
             el: &mut EventLoop<Core>,
             msg: Option<(Message, Priority)>) {
        if self.socket.write(el, self.token, msg).is_err() {
            self.handle_error(core, el);
        }
    }

    fn receive_response(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        match self.socket.read::<Message>() {
            Ok(Some(Message::EchoAddrResp(ext_addr))) => {
                self.terminate(core, el);
                let token = self.token;
                (*self.finish)(core, el, token, Ok(ext_addr.0))
            }
            Ok(None) => (),
            Ok(Some(_)) | Err(_) => self.handle_error(core, el),
        }
    }

    fn handle_error(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        self.terminate(core, el);
        let token = self.token;
        (*self.finish)(core, el, token, Err(()));
    }
}

impl State for GetExtAddr {
    fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, es: EventSet) {
        if es.is_error() || es.is_hup() {
            self.handle_error(core, el);
        } else {
            if es.is_writable() {
                let req = self.request.take();
                self.write(core, el, req);
            }
            if es.is_readable() {
                self.receive_response(core, el)
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.token);
        let _ = el.deregister(&self.socket);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
