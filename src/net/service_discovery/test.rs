use std::time::Duration;
use tokio_core::reactor::{Core, Timeout};
use futures::{future, stream, Future, Stream};
use future_utils::StreamExt;

use net::service_discovery::discover;
use net::service_discovery::server::Server;

#[test]
fn test() {
    let num_servers = 3;
    let num_discovers = 3;
    let starting_port = 45666;

    let mut core = unwrap!(Core::new());
    let handle = core.handle();

    let res = core.run(future::lazy(move || {
        let mut servers = Vec::new();
        for i in 0..num_servers {
            let server = Server::new(&handle, starting_port + i, i);
            servers.push(server);
        }

        let mut futures = Vec::new();
        for i in 0..num_servers {
            for _ in 0..num_discovers {
                let discover = unwrap!(discover::discover::<u16>(&handle, starting_port + i))
                    .until(unwrap!(Timeout::new(Duration::from_secs(1), &handle)).map_err(|e| panic!("{}", e)))
                    .collect()
                    .and_then(move |v| {
                        assert!(v.into_iter().map(|(_, p)| p).collect::<Vec<_>>() == &[i]);
                        Ok(())
                    });
                futures.push(discover);
            }
        }

        stream::futures_unordered(futures)
            .for_each(|()| Ok(()))
            .and_then(|()| Ok(servers))
    }));
    let _servers = unwrap!(res);
}

