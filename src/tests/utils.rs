// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::{PeerInfo, Uid};
use crate::main::{BootstrapCache, Config, Event, EventLoopCore};
use crossbeam;
use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
use mio_extras::channel::channel;
use mio_extras::timer;
use rand::{self, Rng};
use safe_crypto::gen_encrypt_keypair;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
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
    };
}

pub type UniqueId = [u8; 20];
impl Uid for UniqueId {}

/// Generates random unique id.
pub fn rand_uid() -> UniqueId {
    rand::thread_rng().gen()
}

pub fn get_event_sender() -> (crate::CrustEventSender<UniqueId>, Receiver<Event<UniqueId>>) {
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
    config.bootstrap_cache_name = Some(bootstrap_cache_tmp_file().into());
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
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => jh.join(),
        }
    })
}

/// Constructs random bootstrap cache file name.
pub fn bootstrap_cache_tmp_file() -> PathBuf {
    let fname = format!("{:016x}.bootstrap.cache", rand::random::<u64>());
    let mut path = env::temp_dir();
    path.push(fname);
    path
}

/// Creates `Core` for tests with some defaults.
pub fn test_core(bootstrap_cache: BootstrapCache) -> EventLoopCore {
    let (event_tx, _event_rx) = channel();
    let timer = timer::Builder::default().build();
    EventLoopCore::new_for_tests(0, event_tx, timer, bootstrap_cache)
}

/// Bootstrap cache on tmp directory with unique file name.
pub fn test_bootstrap_cache() -> BootstrapCache {
    let cache_file = bootstrap_cache_tmp_file().into();
    BootstrapCache::new(Some(cache_file))
}

/// Constructs peer info with random generated public key.
pub fn peer_info_with_rand_key(addr: SocketAddr) -> PeerInfo {
    let (pk, _) = gen_encrypt_keypair();
    PeerInfo::new(addr, pk)
}
