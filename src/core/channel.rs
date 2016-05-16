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

use mio::{self, EventLoop};
use std::sync::{Arc, mpsc};
use std::sync::atomic::{AtomicBool, Ordering};
pub use std::sync::mpsc::TryRecvError;

use super::{Core, CoreMessage, StateHandle};

pub fn new<T>(event_loop: &EventLoop<Core>, handle: StateHandle) -> (Sender<T>, Receiver<T>) {
    let awake = Arc::new(AtomicBool::new(false));
    let mio_tx = event_loop.channel();
    let (std_tx, std_rx) = mpsc::channel();

    (Sender {
        handle: handle,
        awake: awake.clone(),
        mio_tx: mio_tx,
        std_tx: std_tx,
    },
    Receiver {
        awake: awake,
        std_rx: std_rx,
    })
}

#[derive(Clone)]
pub struct Sender<T> {
    handle: StateHandle,
    awake: Arc<AtomicBool>,
    mio_tx: mio::Sender<CoreMessage>,
    std_tx: mpsc::Sender<T>,
}

impl<T: Send> Sender<T> {
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        try!(self.std_tx.send(value));

        if !self.awake.swap(true, Ordering::SeqCst) {
            try!(self.mio_tx.send(CoreMessage::WakeUp(self.handle)))
        }

        Ok(())
    }
}

pub struct Receiver<T> {
    awake: Arc<AtomicBool>,
    std_rx: mpsc::Receiver<T>,
}

impl<T: Send> Receiver<T> {
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        self.awake.store(false, Ordering::Relaxed);
        self.std_rx.try_recv()
    }
}

#[derive(Debug)]
pub struct SendError<T>(pub Option<T>);

impl<T> From<mpsc::SendError<T>> for SendError<T> {
    fn from(e: mpsc::SendError<T>) -> SendError<T> {
        SendError(Some(e.0))
    }
}

impl<T> From<mio::NotifyError<CoreMessage>> for SendError<T> {
    fn from(_e: mio::NotifyError<CoreMessage>) -> SendError<T> {
        SendError(None)
    }
}