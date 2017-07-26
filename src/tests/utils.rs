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

use common::Uid;
use crossbeam;
use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
use main::{Config, Event};
use std::sync::atomic::{ATOMIC_USIZE_INIT, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

// Receive an event from the given receiver and asserts that it matches the
// given pattern.
macro_rules! expect_event {
    ($rx:expr, $pattern:pat) => {
        match unwrap!($rx.recv_timeout(::std::time::Duration::from_secs(30))) {
            $pattern => (),
            e => panic!("unexpected event {:?}", e),
        }
    };

    ($rx:expr, $pattern:pat => $arm:expr) => {
        match unwrap!($rx.recv_timeout(::std::time::Duration::from_secs(30))) {
            $pattern => $arm,
            e => panic!("unexpected event {:?}", e),
        }
    }
}

pub type UniqueId = [u8; 20];
impl Uid for UniqueId {}

pub fn get_event_sender() -> (::CrustEventSender<UniqueId>, Receiver<Event<UniqueId>>) {
    let (category_tx, _) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    (
        MaidSafeObserver::new(event_tx, MaidSafeEventCategory::Crust, category_tx),
        event_rx,
    )
}

// Generate config with unique bootstrap cache name.
pub fn gen_config() -> Config {
    let mut config = Config::default();
    config.bootstrap_cache_name = Some(gen_bootstrap_cache_name());
    config
}

#[allow(unused)]
pub fn timebomb<R, F>(dur: Duration, f: F) -> R
where
    R: Send,
    F: Send + FnOnce() -> R,
{
    crossbeam::scope(|scope| {
        let thread_handle = thread::current();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let jh = scope.spawn(move || {
            let ret = f();
            drop(done_tx);
            thread_handle.unpark();
            ret
        });
        thread::park_timeout(dur);
        match done_rx.try_recv() {
            Err(mpsc::TryRecvError::Empty) => panic!("Timed out!"),
            Ok(()) |
            Err(mpsc::TryRecvError::Disconnected) => jh.join(),
        }
    })
}

// Generate unique name for the bootstrap cache.
fn gen_bootstrap_cache_name() -> String {
    static COUNTER: AtomicUsize = ATOMIC_USIZE_INIT;
    format!(
        "test{}.bootstrap.cache",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}
