// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

// Defines `Core`, the mio handler and the core of the event loop.

use common::{CommonError, Result, State};
use maidsafe_utilities::thread::{self, Joiner};
use mio::{Event, Events, Poll, PollOpt, Ready, Token};
use mio_extras::channel::{self, Receiver, Sender};
use mio_extras::timer::{Timeout, Timer};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

const EVENT_CAPACITY: usize = 1024;

const CHANNEL_TOKEN_OFFSET: usize = 0;
const TIMER_TOKEN_OFFSET: usize = CHANNEL_TOKEN_OFFSET + 1;
const USER_TOKEN_OFFSET: usize = TIMER_TOKEN_OFFSET + 1;

/// A handle to the main Crust event loop running on a separate thread.
pub struct EventLoop<T> {
    tx: Sender<CoreMessage<T>>,
    _joiner: Joiner,
}

impl<T> EventLoop<T> {
    pub fn send(&self, msg: CoreMessage<T>) -> Result<()> {
        self.tx.send(msg).map_err(|_e| CommonError::CoreMsgTx)
    }
}

impl<T> Drop for EventLoop<T> {
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

/// Spawns event loop in a separate thread and returns a handle to communicate with it.
pub fn spawn_event_loop<T: 'static, F>(
    token_counter_start: usize,
    event_loop_id: Option<&str>,
    init_user_data: F,
) -> Result<EventLoop<T>>
where
    F: 'static + FnOnce() -> Option<T> + Send,
{
    let poll = Poll::new()?;
    let (tx, rx) = channel::channel();
    let timer = Timer::default();

    poll.register(
        &rx,
        Token(token_counter_start + CHANNEL_TOKEN_OFFSET),
        Ready::readable(),
        PollOpt::edge(),
    )?;
    poll.register(
        &timer,
        Token(token_counter_start + TIMER_TOKEN_OFFSET),
        Ready::readable(),
        PollOpt::edge(),
    )?;

    let mut name = "CRUST-Event-Loop".to_string();
    if let Some(id) = event_loop_id {
        name.push_str(": ");
        name.push_str(id);
    }

    let tx_clone = tx.clone();
    let joiner = thread::named(name, move || {
        let user_data = if let Some(user_data) = init_user_data() {
            user_data
        } else {
            error!("Failed to initialize user data.");
            return;
        };

        let core = Core::new(
            token_counter_start + USER_TOKEN_OFFSET,
            tx_clone,
            timer,
            user_data,
        );
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

/// Spins mio event loop until the special exit message is received.
fn event_loop_impl<T>(
    token_counter_start: usize,
    poll: &Poll,
    rx: &Receiver<CoreMessage<T>>,
    mut core: Core<T>,
) -> Result<()> {
    let mut events = Events::with_capacity(EVENT_CAPACITY);

    'event_loop: loop {
        let _ = poll.poll(&mut events, None)?;

        for event in events.iter() {
            match event.token() {
                Token(t) if t == token_counter_start + CHANNEL_TOKEN_OFFSET => {
                    if !event.readiness().is_readable() {
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
                    core.handle_timer(poll, event.readiness())
                }
                _ => core.handle_event(poll, event),
            }
        }
    }

    Ok(())
}

type CoreMessageHandler<T> = Box<FnMut(&mut Core<T>, &Poll) + Send>;
pub struct CoreMessage<T>(Option<CoreMessageHandler<T>>);

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub struct CoreTimer {
    pub state_id: Token,
    pub timer_id: u8,
}

/// Manages states registered on the event loop.
pub struct Core<T> {
    tx: Sender<CoreMessage<T>>,
    timer: Timer<CoreTimer>,
    token_counter: usize,
    states: HashMap<Token, Rc<RefCell<State<T>>>>,
    user_data: T,
}

impl<T> Core<T> {
    fn new(
        token_counter_start: usize,
        tx: Sender<CoreMessage<T>>,
        timer: Timer<CoreTimer>,
        user_data: T,
    ) -> Self {
        Core {
            tx,
            timer,
            token_counter: token_counter_start,
            states: HashMap::new(),
            user_data,
        }
    }

    pub fn sender(&self) -> &Sender<CoreMessage<T>> {
        &self.tx
    }

    pub fn set_timeout(&mut self, interval: Duration, core_timer: CoreTimer) -> Timeout {
        self.timer.set_timeout(interval, core_timer)
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
        state: Rc<RefCell<State<T>>>,
    ) -> Option<Rc<RefCell<State<T>>>> {
        self.states.insert(token, state)
    }

    pub fn remove_state(&mut self, token: Token) -> Option<Rc<RefCell<State<T>>>> {
        self.states.remove(&token)
    }

    pub fn get_state(&self, key: Token) -> Option<Rc<RefCell<State<T>>>> {
        self.states.get(&key).cloned()
    }

    /// Returns an immutable reference to user data stored in `Core`.
    pub fn user_data(&self) -> &T {
        &self.user_data
    }

    /// Returns a mutable reference to user data stored in `Core`.
    pub fn user_data_mut(&mut self) -> &mut T {
        &mut self.user_data
    }

    fn handle_event(&mut self, poll: &Poll, event: Event) {
        if let Some(state) = self.get_state(event.token()) {
            state.borrow_mut().ready(self, poll, event.readiness());
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

impl<T> CoreMessage<T> {
    pub fn new<F: FnOnce(&mut Core<T>, &Poll) + Send + 'static>(f: F) -> Self {
        let mut f = Some(f);
        CoreMessage(Some(Box::new(move |core: &mut Core<T>, poll: &Poll| {
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
