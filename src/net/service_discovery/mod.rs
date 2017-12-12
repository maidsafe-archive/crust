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

mod msg;
mod server;
mod discover;

#[cfg(test)]
mod test;

pub use self::discover::{Discover, discover};
pub use self::server::Server;

use future_utils::{self, DropNotify};
use futures::sync::mpsc::UnboundedReceiver;

use net::service_discovery;
use priv_prelude::*;

pub const SERVICE_DISCOVERY_DEFAULT_PORT: u16 = 5484;

/// Advertises our current set of connectable listening addresses on the local network.
pub struct ServiceDiscovery {
    port: u16,
    _drop_tx: DropNotify,
}

impl ServiceDiscovery {
    pub fn new(
        handle: &Handle,
        config: ConfigFile,
        current_addrs: HashSet<PaAddr>,
        addrs_rx: UnboundedReceiver<HashSet<PaAddr>>,
    ) -> io::Result<ServiceDiscovery> {
        let port = config.read().service_discovery_port.unwrap_or(
            SERVICE_DISCOVERY_DEFAULT_PORT,
        );

        let (drop_tx, drop_rx) = future_utils::drop_notify();
        let mut server = service_discovery::Server::new(
            handle,
            port,
            current_addrs.into_iter().collect::<Vec<_>>(),
        )?;
        let actual_port = server.port();

        handle.spawn({
            addrs_rx
                .chain(future::empty().into_stream())
                .for_each(move |addrs| {
                    server.set_data(addrs.into_iter().collect());
                    Ok(())
                })
                .until(drop_rx.infallible())
                .map(|_unit_opt| ())
        });

        Ok(ServiceDiscovery {
            port: actual_port,
            _drop_tx: drop_tx,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}
