// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

// Defines `Core`, the mio handler and the core of the event loop.

use common::{Result, State};
use maidsafe_utilities::thread::{self, Joiner};
use mio::channel::{self, Receiver, Sender};
use mio::timer::{Timeout, Timer};
use mio::{Event, Events, Poll, PollOpt, Ready, Token};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

const EVENT_CAPACITY: usize = 1024;

const CHANNEL_TOKEN_OFFSET: usize = 0;
const TIMER_TOKEN_OFFSET: usize = CHANNEL_TOKEN_OFFSET + 1;
const USER_TOKEN_OFFSET: usize = TIMER_TOKEN_OFFSET + 1;

pub struct EventLoop {
    tx: Sender<CoreMessage>,
    _joiner: Joiner,
}

impl EventLoop {
    pub fn send(&self, msg: CoreMessage) -> Result<()> {
        self.tx.send(msg)?;
        Ok(())
    }
}

impl Drop for EventLoop {
    fn drop(&mut self) {
        if let Err(e) = self.tx.send(CoreMessage(None)) {
            warn!(
                "Could not send a terminator to event-loop. We will possibly not be able to \
                 gracefully exit. Error: {:?}",
                e
            );
        }
    }
}

pub fn spawn_event_loop(
    token_counter_start: usize,
    event_loop_id: Option<&str>,
) -> Result<EventLoop> {
    let poll = Poll::new()?;
    let (tx, rx) = channel::channel();
    let timer = Timer::default();

    poll.register(
        &rx,
        Token(token_counter_start + CHANNEL_TOKEN_OFFSET),
        Ready::readable() | Ready::error() | Ready::hup(),
        PollOpt::edge(),
    )?;
    poll.register(
        &timer,
        Token(token_counter_start + TIMER_TOKEN_OFFSET),
        Ready::readable() | Ready::error() | Ready::hup(),
        PollOpt::edge(),
    )?;

    let mut name = "CRUST-Event-Loop".to_string();
    if let Some(id) = event_loop_id {
        name.push_str(": ");
        name.push_str(id);
    }

    let tx_clone = tx.clone();
    let joiner = thread::named(name, move || {
        let core = Core::new(token_counter_start + USER_TOKEN_OFFSET, tx_clone, timer);
        match event_loop_impl(token_counter_start, &poll, &rx, core) {
            Ok(()) => trace!("Graceful event loop exit."),
            Err(e) => error!("Event loop killed due to {:?}", e),
        }
    });

    Ok(EventLoop {
        tx,
        _joiner: joiner,
    })
}

fn event_loop_impl(
    token_counter_start: usize,
    poll: &Poll,
    rx: &Receiver<CoreMessage>,
    mut core: Core,
) -> Result<()> {
    let mut events = Events::with_capacity(EVENT_CAPACITY);

    'event_loop: loop {
        let _ = poll.poll(&mut events, None)?;

        for event in events.iter() {
            match event.token() {
                Token(t) if t == token_counter_start + CHANNEL_TOKEN_OFFSET => {
                    if !event.kind().is_readable() {
                        warn!(
                            "Communication channel to event loop errored out: {:?}",
                            event
                        );
                        continue;
                    }

                    loop {
                        let msg = match rx.try_recv() {
                            Ok(msg) => msg,
                            Err(TryRecvError::Empty) => break,
                            Err(TryRecvError::Disconnected) => break 'event_loop,
                        };
                        match msg.0 {
                            Some(mut f) => f(&mut core, poll),
                            None => break 'event_loop,
                        }
                    }
                }
                Token(t) if t == token_counter_start + TIMER_TOKEN_OFFSET => {
                    core.handle_timer(poll, event.kind())
                }
                _ => core.handle_event(poll, event),
            }
        }
    }

    Ok(())
}

pub struct CoreMessage(Option<Box<FnMut(&mut Core, &Poll) + Send>>);

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub struct CoreTimer {
    pub state_id: Token,
    pub timer_id: u8,
}

pub struct Core {
    tx: Sender<CoreMessage>,
    timer: Timer<CoreTimer>,
    token_counter: usize,
    states: HashMap<Token, Rc<RefCell<State>>>,
}

impl Core {
    fn new(token_counter_start: usize, tx: Sender<CoreMessage>, timer: Timer<CoreTimer>) -> Self {
        Core {
            tx,
            timer,
            token_counter: token_counter_start,
            states: HashMap::new(),
        }
    }

    pub fn sender(&self) -> &Sender<CoreMessage> {
        &self.tx
    }

    pub fn set_timeout(&mut self, interval: Duration, core_timer: CoreTimer) -> Result<Timeout> {
        Ok(self.timer.set_timeout(interval, core_timer)?)
    }

    pub fn cancel_timeout(&mut self, timeout: &Timeout) -> Option<CoreTimer> {
        self.timer.cancel_timeout(timeout)
    }

    pub fn get_new_token(&mut self) -> Token {
        let token = Token(self.token_counter);
        self.token_counter += 1;
        token
    }

    pub fn insert_state(
        &mut self,
        token: Token,
        state: Rc<RefCell<State>>,
    ) -> Option<Rc<RefCell<State>>> {
        self.states.insert(token, state)
    }

    pub fn remove_state(&mut self, token: Token) -> Option<Rc<RefCell<State>>> {
        self.states.remove(&token)
    }

    pub fn get_state(&self, key: Token) -> Option<Rc<RefCell<State>>> {
        self.states.get(&key).cloned()
    }

    fn handle_event(&mut self, poll: &Poll, event: Event) {
        if let Some(state) = self.get_state(event.token()) {
            state.borrow_mut().ready(self, poll, event.kind());
        }
    }

    fn handle_timer(&mut self, poll: &Poll, kind: Ready) {
        if !kind.is_readable() {
            warn!("Timer errored out: {:?}", kind);
            return;
        }
        while let Some(core_timer) = self.timer.poll() {
            if let Some(state) = self.get_state(core_timer.state_id) {
                state.borrow_mut().timeout(self, poll, core_timer.timer_id);
            }
        }
    }
}

impl CoreMessage {
    pub fn new<F: FnOnce(&mut Core, &Poll) + Send + 'static>(f: F) -> Self {
        let mut f = Some(f);
        CoreMessage(Some(Box::new(move |core: &mut Core, poll: &Poll| {
            if let Some(f) = f.take() {
                f(core, poll)
            }
        })))
    }
}

impl CoreTimer {
    pub fn new(state_id: Token, timer_id: u8) -> Self {
        CoreTimer { state_id, timer_id }
    }
}
