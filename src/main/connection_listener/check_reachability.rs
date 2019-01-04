// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::{CoreTimer, State};
use crate::main::bootstrap::Cache as BootstrapCache;
use crate::main::EventLoopCore;
use mio::{Poll, PollOpt, Ready, Token};
use mio_extras::timer::Timeout;
use socket_collection::TcpSock;
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

const CHECK_REACHABILITY_TIMEOUT_SEC: u64 = 3;

pub type Finish<T> = Box<FnMut(&mut EventLoopCore, &Poll, Token, Result<T, ()>)>;

/// Does a simple TCP connect to the given address to check, if it's publicly reachable.
/// This state will transit arbitrary user data to the finish callback.
pub struct CheckReachability<T> {
    token: Token,
    socket: TcpSock,
    timeout: Timeout,
    finish: Finish<T>,
    t: T,
}

impl<T> CheckReachability<T>
where
    T: 'static + Clone,
{
    pub fn start(
        core: &mut EventLoopCore,
        poll: &Poll,
        their_listener: SocketAddr,
        t: T,
        finish: Finish<T>,
    ) -> crate::Res<Token> {
        let socket = TcpSock::connect(&their_listener)?;
        let token = core.get_new_token();

        poll.register(&socket, token, Ready::writable(), PollOpt::edge())?;

        let timeout = core.set_timeout(
            Duration::from_secs(CHECK_REACHABILITY_TIMEOUT_SEC),
            CoreTimer::new(token, 0),
        );

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

    fn handle_success(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        self.terminate(core, poll);
        let token = self.token;
        let t = self.t.clone();
        (*self.finish)(core, poll, token, Ok(t));
    }

    fn handle_error(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        self.terminate(core, poll);
        let token = self.token;
        (*self.finish)(core, poll, token, Err(()));
    }
}

impl<T> State<BootstrapCache> for CheckReachability<T>
where
    T: 'static + Clone,
{
    fn ready(&mut self, core: &mut EventLoopCore, poll: &Poll, kind: Ready) {
        if !kind.is_writable() {
            self.handle_error(core, poll);
        } else {
            self.handle_success(core, poll);
        }
    }

    fn terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        let _ = core.cancel_timeout(&self.timeout);
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.socket);
    }

    fn timeout(&mut self, core: &mut EventLoopCore, poll: &Poll, _timer_id: u8) {
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
