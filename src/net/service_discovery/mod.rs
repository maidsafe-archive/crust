// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod discover;
mod msg;
mod server;

#[cfg(test)]
mod test;

pub use self::discover::discover;
pub use self::server::Server;
use crate::config::PeerInfo;
use crate::net::service_discovery;
use crate::priv_prelude::*;
use crate::service;
use future_utils::{self, DropNotify};
use futures::sync::mpsc::UnboundedReceiver;

/// Advertises our current set of connectable listening addresses on the local network.
pub struct ServiceDiscovery {
    port: u16,
    _drop_tx: DropNotify,
}

impl ServiceDiscovery {
    /// Runs service discovery server in the backround.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        handle: &Handle,
        config: &ConfigFile,
        current_addrs: &HashSet<PaAddr>,
        addrs_rx: UnboundedReceiver<HashSet<PaAddr>>,
        our_pk: PublicEncryptKey,
    ) -> io::Result<ServiceDiscovery> {
        let port = config
            .read()
            .service_discovery_port
            .unwrap_or(service::SERVICE_DISCOVERY_DEFAULT_PORT);

        let (drop_tx, drop_rx) = future_utils::drop_notify();
        let current_addrs = current_addrs
            .iter()
            .map(|addr| PeerInfo::new(*addr, our_pk))
            .collect::<Vec<_>>();
        let mut server = service_discovery::Server::new(handle, port, current_addrs)?;
        let actual_port = server.port();

        handle.spawn({
            addrs_rx
                .chain(future::empty().into_stream())
                .for_each(move |addrs| {
                    let addrs = addrs
                        .iter()
                        .map(|addr| PeerInfo::new(*addr, our_pk))
                        .collect();
                    server.set_data(addrs);
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
