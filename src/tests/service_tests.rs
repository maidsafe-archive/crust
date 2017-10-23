use std::fs;
use tokio_core::reactor::Core;
use priv_prelude::*;
use service::Service;
use util;

#[test]
fn start_service() {
    let mut core = unwrap!(Core::new());
    let handle = core.handle();

    let config = unwrap!(ConfigFile::new_temporary());

    let res = core.run({
        Service::with_config(&handle, config, util::random_id())
        .and_then(|_service| Ok(()))
    });

    unwrap!(res);
}

/*

    Things to test:

    can we bootstrap?
    are bootstrap blacklists respected?
    are external reachability requirements respected?
    are whitelists respected?

    can we connect?
    even with no listeners? - not really testable over loopback

*/

