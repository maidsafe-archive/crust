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

use std::rc::Rc;
use std::any::Any;
use std::cell::RefCell;

use nat::{NatError, util};
use socket::Socket;
use message::Message;
use std::net::SocketAddr;
use core::{Context, Core, Priority, State};
use mio::{EventLoop, EventSet, PollOpt, Token};
use mio::tcp::TcpStream;

pub type Finish = Box<FnMut(&mut Core,
                            &mut EventLoop<Core>,
                            Context,
                            Result<SocketAddr, ()>)>;

pub struct GetExtAddr {
    token: Token,
    context: Context,
    socket: Socket,
    request: Option<(Message, Priority)>,
    finish: Finish,
}

impl GetExtAddr {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 local_addr: SocketAddr,
                 peer_stun: &SocketAddr,
                 finish: Finish)
                 -> Result<Context, NatError> {
        let query_socket = try!(util::new_reusably_bound_tcp_socket(&local_addr));
        let query_socket = try!(query_socket.to_tcp_stream());
        let socket = try!(TcpStream::connect_stream(query_socket, peer_stun));

        let socket = Socket::wrap(socket);
        let token = core.get_new_token();
        let context = core.get_new_context();

        let state = GetExtAddr {
            token: token,
            context: context,
            socket: socket,
            request: Some((Message::EchoAddrReq, 0)),
            finish: finish,
        };

        try!(event_loop.register(&state.socket,
                                 token,
                                 EventSet::error() | EventSet::hup() | EventSet::writable(),
                                 PollOpt::edge()));

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));

        Ok(context)
    }

    fn write(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             msg: Option<(Message, Priority)>) {
        if self.socket.write(event_loop, self.token, msg).is_err() {
            self.handle_error(core, event_loop);
        }
    }

    fn receive_response(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match self.socket.read::<Message>() {
            Ok(Some(Message::EchoAddrResp(ext_addr))) => {
                self.terminate(core, event_loop);
                let context = self.context;
                (*self.finish)(core, event_loop, context, Ok(ext_addr.0))
            }
            Ok(None) => (),
            Ok(Some(_)) | Err(_) => self.handle_error(core, event_loop),
        }
    }

    fn handle_error(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        self.terminate(core, event_loop);
        let context = self.context;
        (*self.finish)(core, event_loop, context, Err(()));
    }
}

impl State for GetExtAddr {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet) {
        if event_set.is_error() || event_set.is_hup() {
            self.handle_error(core, event_loop);
        } else {
            if event_set.is_writable() {
                let req = self.request.take();
                self.write(core, event_loop, req);
            }
            if event_set.is_readable() {
                self.receive_response(core, event_loop)
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = core.remove_context(self.token);
        let _ = core.remove_state(self.context);
        let _ = event_loop.deregister(&self.socket);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
