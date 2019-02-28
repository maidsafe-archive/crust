// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::PeerInfo;
use crate::main::{
    BootstrapCache, BootstrapCacheConfig, Config, CrustData, Event, EventLoopCore, Service,
};
use crate::PeerId;
use crossbeam;
use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
use mio_extras::channel::channel;
use mio_extras::timer;
use rand;
use safe_crypto::{gen_encrypt_keypair, gen_sign_keypair, SecretEncryptKey};
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

/// Generates random peer id.
pub fn rand_peer_id_and_enc_sk() -> (PeerId, SecretEncryptKey) {
    let (enc_pk, enc_sk) = gen_encrypt_keypair();
    let (sign_pk, _sign_sk) = gen_sign_keypair();
    let id = PeerId {
        pub_sign_key: sign_pk,
        pub_enc_key: enc_pk,
    };
    (id, enc_sk)
}

pub fn get_event_sender() -> (crate::CrustEventSender, Receiver<Event>) {
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
    config.bootstrap_cache.file_name = Some(bootstrap_cache_tmp_file().into());
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
    EventLoopCore::new_for_tests(0, event_tx, timer, CrustData::new(bootstrap_cache))
}

/// Bootstrap cache on tmp directory with unique file name.
pub fn test_bootstrap_cache() -> BootstrapCache {
    let cache_file = bootstrap_cache_tmp_file().into();
    BootstrapCache::new(BootstrapCacheConfig {
        file_name: Some(cache_file),
        max_size: 100,
    })
}

/// Constructs peer info with random generated public key.
pub fn peer_info_with_rand_key(addr: SocketAddr) -> PeerInfo {
    let (pk, _) = gen_encrypt_keypair();
    PeerInfo::new(addr, pk)
}

/// Generates `Service` instance for testing with default configuration.
pub fn test_service() -> (Service, Receiver<Event>) {
    let config = gen_config();
    let (event_tx, event_rx) = get_event_sender();
    let (peer_id, peer_sk) = rand_peer_id_and_enc_sk();
    let service = unwrap!(Service::with_config(event_tx, config, peer_id, peer_sk));
    (service, event_rx)
}
