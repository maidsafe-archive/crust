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

use common::{Core, CoreTimerId, Socket, SocketAddr, State};
use mio::{EventLoop, EventSet, PollOpt, Timeout, Token};
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

const CHECK_REACHABILITY_TIMEOUT_MS: u64 = 3 * 1000;

pub type Finish<T> = Box<FnMut(&mut Core, &mut EventLoop<Core>, Token, Result<T, ()>)>;

pub struct CheckReachability<T> {
    token: Token,
    socket: Socket,
    timeout: Timeout,
    finish: Finish<T>,
    t: T,
}

impl<T> CheckReachability<T>
    where T: 'static + Clone
{
    pub fn start(core: &mut Core,
                 el: &mut EventLoop<Core>,
                 their_listener: SocketAddr,
                 t: T,
                 finish: Finish<T>)
                 -> ::Res<Token> {
        let socket = Socket::connect(&their_listener)?;
        let token = core.get_new_token();

        el.register(&socket,
                      token,
                      EventSet::error() | EventSet::hup() | EventSet::writable(),
                      PollOpt::edge())?;

        let timeout = el.timeout_ms(CoreTimerId::new(token, 0), CHECK_REACHABILITY_TIMEOUT_MS)?;

        let state = CheckReachability {
            token: token,
            socket: socket,
            timeout: timeout,
            finish: finish,
            t: t,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(token)
    }

    fn handle_success(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        self.terminate(core, el);
        let token = self.token;
        let t = self.t.clone();
        (*self.finish)(core, el, token, Ok(t));
    }

    fn handle_error(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        self.terminate(core, el);
        let token = self.token;
        (*self.finish)(core, el, token, Err(()));
    }
}

impl<T> State for CheckReachability<T>
    where T: 'static + Clone
{
    fn ready(&mut self, core: &mut Core, el: &mut EventLoop<Core>, es: EventSet) {
        if es.is_error() || es.is_hup() || !es.is_writable() {
            self.handle_error(core, el);
        } else {
            self.handle_success(core, el);
        }
    }

    fn terminate(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        let _ = el.clear_timeout(self.timeout);
        let _ = core.remove_state(self.token);
        let _ = el.deregister(&self.socket);
    }

    fn timeout(&mut self, core: &mut Core, el: &mut EventLoop<Core>, _timer_id: u8) {
        trace!("Bootstrapper is external reachability timed out to one of the given IP's. \
                Erroring out for this remote endpoint.");
        self.handle_error(core, el)
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
