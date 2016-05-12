use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;

use state::State;
use mio::{Token, EventLoop, Handler, EventSet};

pub type CoreMessage = Box<FnOnce(&mut Core, &mut EventLoop<Core>) + Send>;
pub type CoreTimeout = ();

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Debug)]
pub struct Context(usize);

pub struct Core {
    token_counter: usize,
    context_counter: usize,
    token_map: HashMap<Token, Context>,
    state_map: HashMap<Context, Rc<RefCell<State>>>,
}

impl Core {
    pub fn new() -> Self {
        Core {
            token_counter: 0,
            context_counter: 0,
            token_map: HashMap::new(),
            state_map: HashMap::new(),
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
}

impl Handler for Core {
    type Timeout = CoreTimeout;
    type Message = CoreMessage;

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
        let state = match self.token_map.get(&token) {
            Some(context) => {
                match self.state_map.get(context) {
                    Some(state) => state.clone(),
                    None => return,
                }
            }
            None => return,
        };

        state.borrow_mut().execute(&mut self, &mut event_loop, token, events);
    }

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {
        msg(&mut self, &mut event_loop);
    }
}
