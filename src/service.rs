// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use core::Core;
use error::Error;
use mio::{EventLoop, Sender, Handler};
use maidsafe_utilities::thread::RaiiThreadJoiner;

/// A structure representing a connection manager.
pub struct Service {
    sender: Sender<<Core as Handler>::Message>,
    _thread_joiner: RaiiThreadJoiner,
}

impl Service {
    /// Constructs a service.
    pub fn new() -> Result<Self, Error> {
        let mut event_loop = try!(EventLoop::new());
        let sender = event_loop.channel();

        let joiner = RaiiThreadJoiner::new(thread!("Crust event loop", move || {
            let mut core = Core::new();
            event_loop.run(&mut core).unwrap();
        }));

        Ok(Service {
            sender: sender,
            _thread_joiner: joiner,
        })
    }

    // TODO: add Service operations like `bootstrap`, `prepare_connection_info`, `connect`, ...
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.sender.send(Box::new(|el: &mut EventLoop<Core>, _: &mut Core| el.shutdown()));
    }
}
