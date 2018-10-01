// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Utilities for use in tests. This module is only available when running with cfg(test)

use compat::{CrustEventSender, Event};
use config_file_handler::current_bin_dir;
use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
use priv_prelude::*;
use rand::{self, Rng};
use std::env;
use std::fs::File;
use std::io::Write;
use std::sync::mpsc::{self, Receiver};

#[allow(unsafe_code)]
pub fn random_vec(size: usize) -> Vec<u8> {
    let mut ret = Vec::with_capacity(size);
    unsafe { ret.set_len(size) };
    rand::thread_rng().fill_bytes(&mut ret[..]);
    ret
}

/// # Arguments
///
/// * `content` - json formatted bootstrap cache to be written to file.
///
/// # Returns
///
/// file name where content was written to.
pub fn write_bootstrap_cache_to_tmp_file(content: &[u8]) -> OsString {
    let mut path = unwrap!(current_bin_dir());
    let fname = format!("{:08x}.bootstrap.cache", rand::random::<u64>());
    path.push(fname.clone());

    let mut f = unwrap!(File::create(path));
    unwrap!(f.write_all(content));
    fname.into()
}

/// Constructs random bootstrap cache file name.
pub fn bootstrap_cache_tmp_file() -> OsString {
    let file_name = format!("{:016x}.bootstrap.cache", rand::random::<u64>());
    let mut path = env::temp_dir();
    path.push(file_name);
    path.into()
}

/// Constructs event sender/receiver pair.
pub fn crust_event_channel() -> (CrustEventSender, Receiver<Event>) {
    let (category_tx, _) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    (
        MaidSafeObserver::new(event_tx, MaidSafeEventCategory::Crust, category_tx),
        event_rx,
    )
}
