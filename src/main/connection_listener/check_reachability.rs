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

use common::{Core, CoreTimer, Socket, SocketAddr, State};
use mio::{Poll, PollOpt, Ready, Token};
use mio::timer::Timeout;
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

const CHECK_REACHABILITY_TIMEOUT_SEC: u64 = 3;

pub type Finish<T> = Box<FnMut(&mut Core, &Poll, Token, Result<T, ()>)>;

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
                 poll: &Poll,
                 their_listener: SocketAddr,
                 t: T,
                 finish: Finish<T>)
                 -> ::Res<Token> {
        let socket = Socket::connect(&their_listener)?;
        let token = core.get_new_token();

        poll.register(&socket,
                      token,
                      Ready::error() | Ready::hup() | Ready::writable(),
                      PollOpt::edge())?;

        let timeout = core.set_timeout(Duration::from_secs(CHECK_REACHABILITY_TIMEOUT_SEC),
                                       CoreTimer::new(token, 0))?;

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

    fn handle_success(&mut self, core: &mut Core, poll: &Poll) {
        self.terminate(core, poll);
        let token = self.token;
        let t = self.t.clone();
        (*self.finish)(core, poll, token, Ok(t));
    }

    fn handle_error(&mut self, core: &mut Core, poll: &Poll) {
        self.terminate(core, poll);
        let token = self.token;
        (*self.finish)(core, poll, token, Err(()));
    }
}

impl<T> State for CheckReachability<T>
    where T: 'static + Clone
{
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_error() || kind.is_hup() || !kind.is_writable() {
            self.handle_error(core, poll);
        } else {
            self.handle_success(core, poll);
        }
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let _ = core.cancel_timeout(&self.timeout);
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.socket);
    }

    fn timeout(&mut self, core: &mut Core, poll: &Poll, _timer_id: u8) {
        trace!("Bootstrapper's external reachability check timed out to one of its given IP's. \
                Erroring out for this remote endpoint.");
        self.handle_error(core, poll)
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
