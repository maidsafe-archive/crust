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

pub struct Connect {
    token: Token,
    context: Context,
    peer_addr: SocketAddr,
    our_pk: Rc<PublicKey>,
    socket: Option<Socket>,
    version_hash: u64,
    cb: Option<Callback>,
}

impl Connect {
    fn new(core: &mut Core,
           event_loop: &mut EventLoop<Core>,
           peer_addr: SocketAddr,
           our_pk: Rc<PublicKey>,
           version_hash: u64,
           cb: Callback)
           -> io::Result<Context> {
        let socket = try!(TcpStream::connect(&peer_addr));

        let token = core.get_new_token();
        let context = core.get_new_context();

        let connect = Connect {
            token: token,
            context: context,
            peer_addr: peer_addr,
            our_pk: our_pk,
            socket: Some(socket),
            version_hash: version_hash,
            cb: Some(cb),
        };

        try!(event_loop.register(connect.socket.as_ref().expect("Logic Error"),
                                 token,
                                 EventSet::error() | EventSet::hup() | EventSet::writable(),
                                 PollOpt::edge()));

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(connect)));

        Ok(context)
    }
}

impl State for Connect {
    fn execute(&mut self,
               core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               token: Token,
               event_set: EventSet) {
        if event_set.is_error() || event_set.is_hup() {
            self.terminate();
            if let Some(cb) = self.cb.take() {
                cb(self.context, Err(self.peer_addr.clone()));
            }
        } else {
            let _ = core.remove_state(&self.context);

            ExchangeMsg::new(core,
                             event_loop,
                             self.token,
                             self.context,
                             self.our_pk.clone(),
                             self.version_hash,
                             self.socket.take().expect("Logic Error"),
                             self.cb.take().expect("Logic Error"));
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Some(context) = core.remove_context(&self.token) {
            let _ = core.remove_state(&context);
        }
        let _ = event_loop.deregister(&self.socket.take().expect("Logic Error"));
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
