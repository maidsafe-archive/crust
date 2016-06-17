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

pub type CoreMessage = Closure;
pub type CoreTimeout = Closure;

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub struct Context(pub usize);

pub struct Core {
    token_counter: usize,
    context_counter: usize,
    contexts: HashMap<Token, Context>,
    states: HashMap<Context, Rc<RefCell<State>>>,
}

impl Core {
    pub fn new() -> Self {
        Self::with_context_counter(0)
    }

    pub fn with_context_counter(context_counter: usize) -> Self {
        Core {
            token_counter: 0,
            context_counter: context_counter,
            contexts: HashMap::new(),
            states: HashMap::new(),
        }
    }

    pub fn get_new_token(&mut self) -> Token {
        let next = Token(self.token_counter);
        self.token_counter = self.token_counter.wrapping_add(1);
        next
    }

    pub fn get_new_context(&mut self) -> Context {
        let next = Context(self.context_counter);
        self.context_counter = self.context_counter.wrapping_add(1);
        next
    }

    pub fn insert_context(&mut self, token: Token, context: Context) -> Option<Context> {
        self.contexts.insert(token, context)
    }

    pub fn insert_state(&mut self,
                        context: Context,
                        state: Rc<RefCell<State>>)
                        -> Option<Rc<RefCell<State>>> {
        self.states.insert(context, state)
    }

    pub fn remove_context(&mut self, token: Token) -> Option<Context> {
        self.contexts.remove(&token)
    }

    pub fn remove_state(&mut self, context: Context) -> Option<Rc<RefCell<State>>> {
        self.states.remove(&context)
    }

    pub fn get_context(&self, token: Token) -> Option<Context> {
        self.contexts.get(&token).cloned()
    }

    pub fn get_state(&self, token: Context) -> Option<Rc<RefCell<State>>> {
        self.states.get(&token).cloned()
    }
}

impl Handler for Core {
    type Timeout = Token;
    type Message = CoreMessage;

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
        match self.get_context(token).and_then(|c| self.get_state(c)) {
            Some(state) => state.borrow_mut().ready(self, event_loop, token, events),
            None => (),
        }
    }

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {
        msg.invoke(self, event_loop)
    }

    fn timeout(&mut self, event_loop: &mut EventLoop<Self>, token: Token) {
        match self.get_context(token).and_then(|c| self.get_state(c)) {
            Some(state) => state.borrow_mut().timeout(self, event_loop, token),
            None => (),
        }
    }
}

impl Default for Core {
    fn default() -> Core {
        Core::new()
    }
}

pub struct Closure(Box<FnMut(&mut Core, &mut EventLoop<Core>) + Send>);

impl Closure {
    pub fn new<F: FnOnce(&mut Core, &mut EventLoop<Core>) + Send + 'static>(f: F) -> Self {
        let mut f = Some(f);
        Closure(Box::new(move |a0: &mut Core, a1: &mut EventLoop<Core>| {
            if let Some(f) = f.take() {
                f(a0, a1)
            }
        }))
    }

    fn invoke(mut self, a0: &mut Core, a1: &mut EventLoop<Core>) {
        (self.0)(a0, a1)
    }
}
