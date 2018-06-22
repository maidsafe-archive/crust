// Copyright 2017 MaidSafe.net limited.
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

use compat::service::{ServiceCommand, ServiceState};
use compat::{CrustEventSender, Uid};
use error::CrustError;
use futures::sync::mpsc::{self, UnboundedSender};
use maidsafe_utilities::thread::{self, Joiner};
use priv_prelude::*;
use std;
use tokio_core::reactor::Core;

/// Event loop that allows you to communicate with *Crust* `Service`.
pub struct EventLoop<UID: Uid> {
    tx: UnboundedSender<ServiceCommand<UID>>,
    _joiner: Joiner,
}

impl<UID: Uid> EventLoop<UID> {
    /// Tell event loop to execute function with `Service` context meaning called function receives
    /// `ServiceState` as an argument.
    pub fn send(&self, msg: ServiceCommand<UID>) {
        unwrap!(self.tx.unbounded_send(msg));
    }
}

/// Runs Tokio futures based *Crust* `Service` and event loop to communicate with it.
pub fn spawn_event_loop<UID: Uid>(
    event_loop_id: Option<&str>,
    event_tx: CrustEventSender<UID>,
    our_uid_data: Vec<u8>,
    config: ConfigFile,
) -> Result<EventLoop<UID>, CrustError> {
    let mut name = "CRUST-Event-Loop".to_string();
    if let Some(id) = event_loop_id {
        name.push_str(": ");
        name.push_str(id);
    }

    let (result_tx, result_rx) = std::sync::mpsc::channel::<Result<_, CrustError>>();
    let our_sk = SecretId::new();

    let joiner = thread::named(name, move || {
        let try = move || {
            let mut core = Core::new()?;
            let handle = core.handle();

            let service = core.run(::Service::with_config(
                &handle,
                config,
                our_sk,
                our_uid_data,
            ))?;

            let service_state = ServiceState::new(service, event_tx);

            Ok((core, service_state))
        };

        match try() {
            Ok((mut core, mut service_state)) => {
                let handle = core.handle();
                let (tx, rx) = mpsc::unbounded::<ServiceCommand<UID>>();
                unwrap!(result_tx.send(Ok(tx)));
                unwrap!(core.run({
                    rx.for_each(move |cb| {
                        cb.call_box(&mut service_state);
                        Ok(())
                    }).and_then(move |()| {
                        Timeout::new(Duration::from_millis(200), &handle).infallible()
                    })
                }));
            }
            Err(e) => {
                unwrap!(result_tx.send(Err(e)));
            }
        }
    });

    let tx = unwrap!(result_rx.recv())?;

    Ok(EventLoop {
        tx,
        _joiner: joiner,
    })
}
