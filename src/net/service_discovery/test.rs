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

use future_utils::StreamExt;
use futures::{Future, Stream, future, stream};

use net::service_discovery::discover;
use net::service_discovery::server::Server;
use std::time::Duration;
use tokio_core::reactor::{Core, Timeout};

#[test]
fn test() {
    let num_servers = 3;
    let num_discovers = 3;
    let starting_port = 45_666;

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
                    .until(
                        unwrap!(Timeout::new(Duration::from_secs(1), &handle))
                            .map_err(|e| panic!("{}", e)),
                    )
                    .collect()
                    .and_then(move |v| {
                        assert_eq!(v.into_iter().map(|(_, p)| p).collect::<Vec<_>>(), &[i]);
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
