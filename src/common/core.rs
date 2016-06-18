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
// Defines `Core`, the mio handler and the core of the event loop.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use common::State;
use mio::{EventLoop, EventSet, Handler, Token};

pub struct CoreMessage(Box<FnMut(&mut Core, &mut EventLoop<Core>) + Send>);

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub struct CoreTimerId {
    pub state_id: Token,
    pub timer_id: u8,
}

pub struct Core {
    token_counter: usize,
    states: HashMap<Token, Rc<RefCell<State>>>,
}

impl Core {
    pub fn new() -> Self {
        Self::with_token_counter(0)
    }

    pub fn with_token_counter(token_counter: usize) -> Self {
        Core {
            token_counter: token_counter,
            states: HashMap::new(),
        }
    }

    pub fn get_new_token(&mut self) -> Token {
        let next = Token(self.token_counter);
        self.token_counter += 1;
        next
    }

    pub fn insert_state(&mut self,
                        token: Token,
                        state: Rc<RefCell<State>>)
                        -> Option<Rc<RefCell<State>>> {
        self.states.insert(token, state)
    }

    pub fn remove_state(&mut self, token: Token) -> Option<Rc<RefCell<State>>> {
        self.states.remove(&token)
    }

    pub fn get_state(&self, key: Token) -> Option<Rc<RefCell<State>>> {
        self.states.get(&key).cloned()
    }
}

impl Handler for Core {
    type Timeout = CoreTimerId;
    type Message = CoreMessage;

    fn ready(&mut self, el: &mut EventLoop<Self>, token: Token, es: EventSet) {
        if let Some(state) = self.get_state(token) {
            state.borrow_mut().ready(self, el, es);
        }
    }

    fn notify(&mut self, el: &mut EventLoop<Self>, msg: Self::Message) {
        msg.invoke(self, el)
    }

    fn timeout(&mut self, el: &mut EventLoop<Self>, timeout: Self::Timeout) {
        if let Some(state) = self.get_state(timeout.state_id) {
            state.borrow_mut().timeout(self, el, timeout.timer_id);
        }
    }
}

impl CoreMessage {
    pub fn new<F: FnOnce(&mut Core, &mut EventLoop<Core>) + Send + 'static>(f: F) -> Self {
        let mut f = Some(f);
        CoreMessage(Box::new(move |core: &mut Core, el: &mut EventLoop<Core>| {
            if let Some(f) = f.take() {
                f(core, el)
            }
        }))
    }

    fn invoke(mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        (self.0)(core, el)
    }
}

impl CoreTimerId {
    pub fn new(state_id: Token, timer_id: u8) -> Self {
        CoreTimerId {
            state_id: state_id,
            timer_id: timer_id,
        }
    }
}
