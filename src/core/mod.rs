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

use mio::{Token, EventLoop, EventSet, Handler, NotifyError, Sender};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;

pub use self::state::State;

pub mod state;
pub mod channel;

pub enum CoreMessage {
    // Execute the given closure on the event loop.
    Post(Closure),
    // Wake the state identified by the handle up.
    WakeUp(StateHandle),
}

impl CoreMessage {
    pub fn post<F>(f: F) -> Self
        where F: FnOnce(&mut Core, &mut EventLoop<Core>) + Send + 'static
    {
        CoreMessage::Post(Closure::new(f))
    }
}

pub type CoreTimeout = ();

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub struct StateHandle(usize);

pub struct Core {
    token_gen: IndexGenerator,
    state_handle_gen: IndexGenerator,
    state_handles: HashMap<Token, StateHandle>,
    states: HashMap<StateHandle, Rc<RefCell<State>>>,
    mio_tx: Sender<CoreMessage>,
}

impl Core {
    pub fn run(mut event_loop: EventLoop<Core>) -> io::Result<()> {
        let mut core = Core {
            token_gen: IndexGenerator::new(),
            state_handle_gen: IndexGenerator::new(),
            state_handles: HashMap::new(),
            states: HashMap::new(),
            mio_tx: event_loop.channel(),
        };

        event_loop.run(&mut core)
    }

    pub fn get_new_token(&mut self) -> Token {
        Token(self.token_gen.next())
    }

    pub fn get_new_state_handle(&mut self) -> StateHandle {
        StateHandle(self.state_handle_gen.next())
    }

    pub fn insert_state_handle(&mut self, key: Token, val: StateHandle) -> Option<StateHandle> {
        self.state_handles.insert(key, val)
    }

    pub fn insert_state<T>(&mut self, key: StateHandle, val: T) -> Option<Rc<RefCell<State>>>
        where T: State + 'static
    {
        self.states.insert(key, Rc::new(RefCell::new(val)))
    }

    pub fn remove_state_handle(&mut self, key: &Token) -> Option<StateHandle> {
        self.state_handles.remove(key)
    }

    pub fn remove_state(&mut self, key: &StateHandle) -> Option<Rc<RefCell<State>>> {
        self.states.remove(key)
    }

    pub fn get_state_handle(&self, key: &Token) -> Option<StateHandle> {
        self.state_handles.get(key).map(|h| *h)
    }

    pub fn get_state(&self, key: &StateHandle) -> Option<Rc<RefCell<State>>> {
        self.states.get(key).map(|s| s.clone())
    }

    pub fn get_state_by_token(&self, token: &Token) -> Option<Rc<RefCell<State>>> {
        self.get_state_handle(token).and_then(|h| self.get_state(&h))
    }

    pub fn remove_state_by_token(&mut self, token: &Token) -> Option<Rc<RefCell<State>>> {
        self.remove_state_handle(token).and_then(|h| self.remove_state(&h))
    }

    pub fn wake_up(&self, handle: StateHandle) -> Result<(), NotifyError<CoreMessage>> {
        self.mio_tx.send(CoreMessage::WakeUp(handle))
    }
}

impl Handler for Core {
    type Timeout = CoreTimeout;
    type Message = CoreMessage;

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
        let state = match self.get_state_by_token(&token) {
            Some(state) => state,
            None => return,
        };

        state.borrow_mut().ready(self, event_loop, token, events);
    }

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {
        match msg {
            CoreMessage::Post(closure) => closure.invoke(self, event_loop),
            CoreMessage::WakeUp(handle) => {
                if let Some(state) = self.get_state(&handle) {
                    state.borrow_mut().notify(self, event_loop);
                }
            }
        }
    }
}

// Helper struct to generate sequence of unique indices. Call `next` to
// generate new index.
struct IndexGenerator(usize);

impl IndexGenerator {
  fn new() -> Self {
    IndexGenerator(0)
  }

  fn next(&mut self) -> usize {
    let next = self.0;
    self.0 = self.0.wrapping_add(1);
    next
  }
}

// Workaround for Box<FnOnce>
pub struct Closure(Box<FnMut(&mut Core, &mut EventLoop<Core>) + Send>);

impl Closure {
    fn new<F : FnOnce(&mut Core, &mut EventLoop<Core>) + Send + 'static>(f: F) -> Self {
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
