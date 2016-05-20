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
use std::cell::RefCell;
use std::collections::HashMap;

use state::State;
use mio::{Token, EventLoop, Handler, EventSet};

pub type CoreTimeout = ();

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Debug, Copy)]
pub struct Context(usize);

pub struct Core {
    token_counter: usize,
    context_counter: usize,
    contexts: HashMap<Token, Context>,
    states: HashMap<Context, Rc<RefCell<State>>>,
}

impl Core {
    pub fn new() -> Self {
        Core {
            token_counter: 0,
            context_counter: 0,
            contexts: HashMap::new(),
            states: HashMap::new(),
        }
    }

    pub fn get_new_token(&mut self) -> Token {
        let token_counter = self.token_counter;
        self.token_counter = token_counter.wrapping_add(1);

        Token(token_counter)
    }

    pub fn get_new_context(&mut self) -> Context {
        let context_counter = self.context_counter;
        self.context_counter = context_counter.wrapping_add(1);

        Context(context_counter)
    }

    pub fn insert_context(&mut self, key: Token, val: Context) -> Option<Context> {
        self.contexts.insert(key, val)
    }

    pub fn insert_state(&mut self,
                        key: Context,
                        val: Rc<RefCell<State>>)
                        -> Option<Rc<RefCell<State>>> {
        self.states.insert(key, val)
    }

    pub fn remove_context(&mut self, key: &Token) -> Option<Context> {
        self.contexts.remove(key)
    }

    pub fn remove_state(&mut self, key: &Context) -> Option<Rc<RefCell<State>>> {
        self.states.remove(key)
    }

    pub fn _get_context(&self, key: &Token) -> Option<&Context> {
        self.contexts.get(key)
    }

    pub fn get_state(&self, key: &Context) -> Option<&Rc<RefCell<State>>> {
        self.states.get(key)
    }
}

impl Handler for Core {
    type Timeout = CoreTimeout;
    type Message = CoreMessage;

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
        let state = match self.contexts.get(&token) {
            Some(context) => {
                match self.states.get(context) {
                    Some(state) => state.clone(),
                    None => return,
                }
            }
            None => return,
        };

        state.borrow_mut().execute(self, event_loop, token, events);
    }

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {
        msg.invoke(self, event_loop);
    }
}

// Workaround for Box<FnOnce>.
pub struct CoreMessage(Box<FnMut(&mut Core, &mut EventLoop<Core>) + Send>);

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
