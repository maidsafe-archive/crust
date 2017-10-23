use futures::sync::mpsc::UnboundedReceiver;
use future_utils::{self, DropNotify};
use priv_prelude::*;

use net::service_discovery;

pub const SERVICE_DISCOVERY_DEFAULT_PORT: u16 = 5484;

/// Advertises our current set of connectable listening addresses on the local network.
pub struct ServiceDiscovery {
    port: u16,
    drop_tx: DropNotify,
}

impl ServiceDiscovery {
    pub fn new(
        handle: &Handle,
        config: ConfigFile,
        current_addrs: HashSet<SocketAddr>,
        addrs_rx: UnboundedReceiver<HashSet<SocketAddr>>,
    ) -> io::Result<ServiceDiscovery> {
        let port = config.read().service_discovery_port.unwrap_or(
            SERVICE_DISCOVERY_DEFAULT_PORT,
        );

        let (drop_tx, drop_rx) = future_utils::drop_notify();
        let mut server = service_discovery::Server::new(handle, port, current_addrs.into_iter().collect::<Vec<_>>())?;
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
            drop_tx,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use priv_prelude::*;
    use tokio_core::reactor::Core;
    use futures::sync::mpsc;
    use env_logger;

    #[test]
    fn service_discovery() {
        let _logger = env_logger::init();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();

        let config = unwrap!(ConfigFile::new_temporary());
        unwrap!(config.write()).service_discovery_port = Some(0);
        let (tx, rx) = mpsc::unbounded();
        
        let sd = unwrap!(ServiceDiscovery::new(&handle, config, hashset!{}, rx));
        let port = sd.port();

        let f = {
            unwrap!(service_discovery::discover::<HashSet<SocketAddr>>(&handle, port))
            .until({
                unwrap!(Timeout::new(Duration::from_millis(200), &handle))
                .map_err(|e| panic!(e))
            })
            .collect()
            .and_then(move |v| {
                assert!(v.into_iter().any(|(_, addrs)| addrs == hashset!{}));

                let some_addrs = hashset!{addr!("1.2.3.4:555"), addr!("5.4.3.2:111")};
                unwrap!(tx.unbounded_send(some_addrs.clone()));

                let handle0 = handle.clone();

                unwrap!(Timeout::new(Duration::from_millis(100), &handle))
                .map_err(|e| panic!(e))
                .map(move |()| unwrap!(service_discovery::discover::<HashSet<SocketAddr>>(&handle0, port)))
                .flatten_stream()
                .until({
                    unwrap!(Timeout::new(Duration::from_millis(200), &handle))
                    .map_err(|e| panic!(e))
                })
                .collect()
                .map(move |v| {
                    assert!(v.into_iter().any(|(_, addrs)| addrs == some_addrs));
                    drop(sd);
                })
            })
        };
        let res = core.run(f);
        unwrap!(res)
    }
}

