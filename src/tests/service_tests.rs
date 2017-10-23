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

