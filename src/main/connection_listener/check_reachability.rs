// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use common::{Core, CoreTimer, Socket, State};
use mio::{Poll, PollOpt, Ready, Token};
use mio::timer::Timeout;
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
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
where
    T: 'static + Clone,
{
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        their_listener: SocketAddr,
        t: T,
        finish: Finish<T>,
    ) -> ::Res<Token> {
        let socket = Socket::connect(&their_listener)?;
        let token = core.get_new_token();

        poll.register(
            &socket,
            token,
            Ready::error() | Ready::hup() | Ready::writable(),
            PollOpt::edge(),
        )?;

        let timeout = core.set_timeout(
            Duration::from_secs(CHECK_REACHABILITY_TIMEOUT_SEC),
            CoreTimer::new(token, 0),
        )?;

        let state = CheckReachability {
            token,
            socket,
            timeout,
            finish,
            t,
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
where
    T: 'static + Clone,
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
        trace!(
            "Bootstrapper's external reachability check timed out to one of its given IP's. \
                Erroring out for this remote endpoint."
        );
        self.handle_error(core, poll)
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
