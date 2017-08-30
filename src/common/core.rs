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

use common::{self, State};
use futures;
use futures::{Async, Future, Stream, future};
use futures::sync::{mpsc, oneshot};
use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use maidsafe_utilities::thread::{self, Joiner};
use mio::{Evented, Poll, PollOpt, Ready, Token};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::time::Duration;
use tokio_core;
use tokio_core::reactor;
use tokio_core::reactor::{Handle, PollEvented};

pub struct CoreMessage(Option<Box<FnMut(&mut Core, &FakePoll) + Send>>);

struct TimeoutData {
    tokio_timeout: reactor::Timeout,
    cancel_channel: oneshot::Receiver<()>,
    timer_id: u8,
}

enum TaskMessage {
    Register(PollEvented<FakeEvented>, Ready),
    Reregister(Ready),
    Deregister,
    AddTimeout(TimeoutData),
    ChangeState(Option<Rc<RefCell<State>>>),
}

/// Maintains a set of tasks on the the tokio event loop, one for each token.
/// Each task has a channel which can be used to send messages to it.
struct TaskChannelMap {
    handle: Handle,
    channel_map: HashMap<Token, UnboundedSender<TaskMessage>>,
}

impl TaskChannelMap {
    pub fn new(handle: Handle) -> Rc<RefCell<TaskChannelMap>> {
        let ret = TaskChannelMap {
            handle: handle,
            channel_map: HashMap::new(),
        };
        Rc::new(RefCell::new(ret))
    }

    /// Send a message to the task identified by the token. Will create the task if need be.
    pub fn send_msg_and_maybe_create_task(
        &mut self,
        core: Rc<RefCell<Core>>,
        token: Token,
        mut msg: TaskMessage,
    ) {
        loop {
            let handle = &self.handle;
            msg = match self.channel_map
                .entry(token)
                .or_insert_with(|| TaskState::spawn(core.clone(), handle))
                .send(msg) {
                Err(send_error) => send_error.into_inner(),
                Ok(()) => return,
            };

            // We had a task registered under this token, but it died. Drop the defunct sender,
            // loop around and create a new task.
            let _ = self.channel_map.remove(&token);
        }
    }

    /// Send a message to the task identified by the token. The task must exist or else this method
    /// will panic.
    pub fn send_msg_or_panic(&mut self, token: Token, msg: TaskMessage) {
        let channel = unwrap!(self.channel_map.get(&token), "Unknown token/task!");
        unwrap!(channel.send(msg))
    }
}

/// Interface to the set of crust state machines.
pub struct Core {
    task_channels: Rc<RefCell<TaskChannelMap>>,
    states: HashMap<Token, Rc<RefCell<State>>>,
    token_counter: usize,
    sender: UnboundedSender<CoreMessage>,
    handle: Handle,
    self_ref: Option<Rc<RefCell<Core>>>,
}

/// Handles {,re,de}registration of file-descriptors on tokens.
pub struct FakePoll {
    task_channels: Rc<RefCell<TaskChannelMap>>,
    core: Rc<RefCell<Core>>,
    handle: Handle,
}

/// The state machine which runs on the tokio event loop, executing a `State`.
struct TaskState {
    core: Rc<RefCell<Core>>,
    channel: UnboundedReceiver<TaskMessage>,
    poll_evented: Option<PollEvented<FakeEvented>>,
    timeouts: Vec<TimeoutData>,
    ready_mask: Option<Ready>,
    state: Option<Rc<RefCell<State>>>,
}

impl TaskState {
    // Create a task on the tokio event loop, returning a channel to it.
    pub fn spawn(core: Rc<RefCell<Core>>, handle: &Handle) -> UnboundedSender<TaskMessage> {
        let (tx, rx) = mpsc::unbounded();
        let task_state = TaskState {
            core: core,
            channel: rx,
            poll_evented: None,
            timeouts: vec![],
            state: None,
            ready_mask: None,
        };
        handle.spawn(task_state);
        tx
    }
}

impl Future for TaskState {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<()>, ()> {
        let mut core = self.core.borrow_mut();
        let poll = core.make_poll();
        loop {
            // Process all incoming messages.
            match self.channel.poll()? {
                Async::Ready(Some(msg)) => {
                    match msg {
                        TaskMessage::Register(poll_evented, ready) => {
                            self.poll_evented = Some(poll_evented);
                            self.ready_mask = Some(ready);
                        }
                        TaskMessage::Reregister(ready) => {
                            self.ready_mask = Some(ready);
                        }
                        TaskMessage::Deregister => {
                            self.ready_mask = None;
                        }
                        TaskMessage::AddTimeout(timeout_data) => {
                            self.timeouts.push(timeout_data);
                        }
                        TaskMessage::ChangeState(state) => {
                            self.state = state;
                        }
                    }
                }
                Async::Ready(None) => {
                    return Ok(Async::Ready(()));
                }
                Async::NotReady => break,
            }
        }
        // Only process timeouts and file events if we have a state.
        if let Some(ref state) = self.state {
            let mut i = 0;
            while i < self.timeouts.len() {
                // Process each timeout
                {
                    let mut timeout = &mut self.timeouts[i];
                    match timeout.cancel_channel.poll() {
                        Ok(Async::Ready(())) => (), // Timeout cancelled.
                        _ => {
                            match timeout.tokio_timeout.poll() {
                                Ok(Async::NotReady) => {
                                    // We are still waiting on this timeout.
                                    // Proceed to next timeout without removing this one.
                                    i += 1;
                                    continue;
                                }
                                Ok(Async::Ready(())) => {
                                    // Timeout fired.
                                    state.borrow_mut().timeout(&mut core, &poll, timeout.timer_id);
                                }
                                Err(e) => {
                                    warn!("Error in timeout: {}", e);
                                }
                            }
                        }
                    }
                };
                // We are no longer waiting on this timeout. So remove it.
                let _ = self.timeouts.swap_remove(i);
            }
            // If ready_mask is None then we either don't have a file descriptor, or it was
            // deregistered.
            if let Some(ready_mask) = self.ready_mask {
                let poll_evented = unwrap!(
                    self.poll_evented.as_ref(),
                    "This can't not be set if ready_mask is set"
                );
                if let Async::Ready(ready) = poll_evented.poll_ready(ready_mask) {
                    state.borrow_mut().ready(&mut core, &poll, ready);
                    if ready.is_readable() {
                        poll_evented.need_read();
                    }
                    if ready.is_writable() {
                        poll_evented.need_write();
                    }
                }
            }
        }
        if self.ready_mask.is_none() && self.timeouts.is_empty() {
            // We're not waiting on any IO events or timeouts, so we can let this task die.
            Ok(Async::Ready(()))
        } else {
            // This task is still doing something. Keep it running.
            Ok(Async::NotReady)
        }
    }
}

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub struct CoreTimer {
    pub state_id: Token,
    pub timer_id: u8,
}

pub struct Timeout {
    inner: RefCell<Option<TimeoutInner>>,
}

struct TimeoutInner {
    cancel_channel: oneshot::Sender<()>,
    core_timer: CoreTimer,
}

impl Core {
    fn new(
        token_counter_start: usize,
        tx: UnboundedSender<CoreMessage>,
        handle: Handle,
        task_channels: Rc<RefCell<TaskChannelMap>>,
    ) -> Rc<RefCell<Core>> {
        let core = Core {
            task_channels: task_channels,
            states: HashMap::new(),
            token_counter: token_counter_start,
            sender: tx,
            handle: handle,
            self_ref: None,
        };
        let core_ref = Rc::new(RefCell::new(core));
        let core_ref_cloned = core_ref.clone();
        core_ref.borrow_mut().self_ref = Some(core_ref_cloned);
        core_ref
    }

    fn make_poll(&self) -> FakePoll {
        FakePoll {
            task_channels: self.task_channels.clone(),
            core: unwrap!(self.self_ref.clone()),
            handle: self.handle.clone(),
        }
    }

    pub fn sender(&self) -> &UnboundedSender<CoreMessage> {
        &self.sender
    }

    pub fn set_timeout(
        &mut self,
        interval: Duration,
        core_timer: CoreTimer,
    ) -> common::Result<Timeout> {
        // Tell the task with the given token to wake up on a timeout.

        let core = unwrap!(self.self_ref.clone());
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let timeout_data = TimeoutData {
            tokio_timeout: reactor::Timeout::new(interval, &self.handle)?,
            cancel_channel: cancel_rx,
            timer_id: core_timer.timer_id,
        };
        let msg = TaskMessage::AddTimeout(timeout_data);
        self.task_channels
            .borrow_mut()
            .send_msg_and_maybe_create_task(core, core_timer.state_id, msg);
        Ok(Timeout {
            inner: RefCell::new(Some(TimeoutInner {
                cancel_channel: cancel_tx,
                core_timer: core_timer,
            })),
        })
    }

    pub fn cancel_timeout(&mut self, timeout: &Timeout) -> Option<CoreTimer> {
        if let Some(inner) = timeout.inner.borrow_mut().take() {
            // Tell the task to cancel the timeout (if it still exists).
            let _ = inner.cancel_channel.send(());
            Some(inner.core_timer)
        } else {
            None
        }
    }

    pub fn insert_state(
        &mut self,
        token: Token,
        state: Rc<RefCell<State>>,
    ) -> Option<Rc<RefCell<State>>> {
        let core = unwrap!(self.self_ref.clone());
        let msg = TaskMessage::ChangeState(Some(state.clone()));
        self.task_channels
            .borrow_mut()
            .send_msg_and_maybe_create_task(core, token, msg);
        self.states.insert(token, state)
    }

    pub fn get_state(&self, token: Token) -> Option<Rc<RefCell<State>>> {
        self.states.get(&token).cloned()
    }

    pub fn remove_state(&mut self, token: Token) -> Option<Rc<RefCell<State>>> {
        let msg = TaskMessage::ChangeState(None);
        self.task_channels.borrow_mut().send_msg_or_panic(
            token,
            msg,
        );
        self.states.remove(&token)
    }

    pub fn get_new_token(&mut self) -> Token {
        let token = Token(self.token_counter);
        self.token_counter += 1;
        token
    }
}

impl FakePoll {
    pub fn register<E: Evented + 'static>(
        &self,
        e: &E,
        token: Token,
        ready: Ready,
    ) -> io::Result<()> {
        let core = self.core.clone();

        // We don't actually need to keep the `Evented` object around after calling
        // `PollEvented::new`, So we set it to `None` (since we can't keep it).
        let mut pollable = PollEvented::new(FakeEvented::new(e), &self.handle)?;
        pollable.get_mut().ptr = None;


        let msg = TaskMessage::Register(pollable, ready);
        self.task_channels
            .borrow_mut()
            .send_msg_and_maybe_create_task(core, token, msg);
        Ok(())
    }

    pub fn reregister<E: Evented + 'static>(
        &self,
        _e: &E,
        token: Token,
        ready: Ready,
    ) -> io::Result<()> {
        let msg = TaskMessage::Reregister(ready);
        self.task_channels.borrow_mut().send_msg_or_panic(
            token,
            msg,
        );
        Ok(())
    }

    pub fn deregister(&self, token: Token) -> io::Result<()> {
        let msg = TaskMessage::Deregister;
        self.task_channels.borrow_mut().send_msg_or_panic(
            token,
            msg,
        );
        Ok(())
    }
}

pub struct EventLoop {
    tx: UnboundedSender<CoreMessage>,
    _joiner: Joiner,
}

impl EventLoop {
    pub fn send(&self, msg: CoreMessage) -> ::Res<()> {
        Ok(self.tx.send(msg)?)
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
) -> common::Result<EventLoop> {
    let (tx, rx) = futures::sync::mpsc::unbounded();

    let mut name = "CRUST-Event-Loop".to_string();
    if let Some(id) = event_loop_id {
        name.push_str(": ");
        name.push_str(id);
    }

    let tx_clone = tx.clone();
    let joiner = thread::named(name, move || match event_loop_impl(
        token_counter_start,
        rx,
        tx_clone,
    ) {
        Ok(()) => trace!("Graceful event loop exit."),
        Err(e) => error!("Event loop killed due to {:?}", e),
    });

    Ok(EventLoop {
        tx: tx,
        _joiner: joiner,
    })
}

fn event_loop_impl(
    token_counter_start: usize,
    rx: UnboundedReceiver<CoreMessage>,
    tx: UnboundedSender<CoreMessage>,
) -> ::Res<()> {
    let mut tokio_core = tokio_core::reactor::Core::new()?;
    let handle = tokio_core.handle();
    let task_channels = TaskChannelMap::new(handle.clone());
    let core = Core::new(
        token_counter_start,
        tx,
        handle.clone(),
        task_channels.clone(),
    );
    let server = rx.for_each(move |crust_msg| {
        let mut f = match crust_msg.0 {
            Some(f) => f,
            None => return future::err(()).boxed(),
        };
        let mut core = core.borrow_mut();
        let poll = core.make_poll();
        f(&mut core, &poll);
        future::ok(()).boxed()
    });
    let _ = tokio_core.run(server);
    Ok(())
}

impl CoreMessage {
    pub fn new<F: FnOnce(&mut Core, &FakePoll) + Send + 'static>(f: F) -> Self {
        let mut f = Some(f);
        CoreMessage(Some(Box::new(
            move |core: &mut Core, poll: &FakePoll| if let Some(f) =
                f.take()
            {
                f(core, poll)
            },
        )))
    }
}

impl CoreTimer {
    pub fn new(state_id: Token, timer_id: u8) -> Self {
        CoreTimer {
            state_id: state_id,
            timer_id: timer_id,
        }
    }
}

struct FakeEvented {
    pub ptr: Option<*const Evented>,
}

impl FakeEvented {
    pub fn new<E: Evented + 'static>(e: &E) -> FakeEvented {
        FakeEvented { ptr: Some(e) }
    }
}

impl Evented for FakeEvented {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        // We know this is memory-safe since we set `ptr` to `None` immediately after registering
        // the `Evented` with tokio's event loop, while the `Evented` is still alive and in-scope.
        // If these functions somehow get called when they're not meant to, the `Option` will make
        // sure we panic instead of segfault/UB.
        unsafe { (*unwrap!(self.ptr)).register(poll, token, interest, opts) }
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        unsafe { (*unwrap!(self.ptr)).reregister(poll, token, interest, opts) }
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        unsafe { (*unwrap!(self.ptr)).deregister(poll) }
    }
}
