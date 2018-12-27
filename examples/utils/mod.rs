// Copyright 2018 MaidSafe.net limited.
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

use crust::PubConnectionInfo;
use future_utils::{bi_channel, thread_future, BoxFuture, FutureExt};
use futures::future::Future;
use futures::Stream;
use serde_json;
use std::io;
use tokio_core::reactor::Handle;
use void::Void;

// Some peer ID boilerplate.

/// Reads single line from stdin.
pub fn read_line() -> BoxFuture<String, Void> {
    thread_future(|| {
        let stdin = io::stdin();
        let mut line = String::new();
        unwrap!(stdin.read_line(&mut line));
        line
    })
    .into_boxed()
}

/// Spawns background task that prints our connection info and waits for us to input theirs.
#[allow(unused)]
pub fn exchange_conn_info(
    handle: &Handle,
    ci_channel2: bi_channel::UnboundedBiChannel<PubConnectionInfo>,
) {
    let exchange_ci = ci_channel2
        .into_future()
        .and_then(|(our_ci_opt, ci_channel2)| {
            let our_ci = unwrap!(our_ci_opt);
            println!(
                "Public connection information:\n{}\n",
                unwrap!(serde_json::to_string(&our_ci))
            );
            println!("Enter remote peer public connection info:");

            read_line().infallible().and_then(move |ln| {
                let their_info: PubConnectionInfo = unwrap!(serde_json::from_str(&ln));
                unwrap!(ci_channel2.unbounded_send(their_info));
                Ok(())
            })
        })
        .then(|_| Ok(()));
    handle.spawn(exchange_ci);
}
