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

use maidsafe_utilities::thread::RaiiThreadJoiner;
use mio::{self, EventLoop, /*EventSet,*/ Sender, Token};

use error::Error;
use message::Message;

/// A structure representing a connection manager.
pub struct Service {
    sender: Sender<Message>,
    _thread_joiner: RaiiThreadJoiner,
}

impl Service {
    /// Constructs a service.
    pub fn new() -> Result<Self, Error> {
        let mut event_loop = try!(EventLoop::new());
        let sender = event_loop.channel();

        let joiner = RaiiThreadJoiner::new(thread!("Crust event loop", move || {
            let mut handler = Handler::new();

            // TODO: how to handle Err here?
            event_loop.run(&mut handler).unwrap();
        }));

        Ok(Service{
            sender: sender,
            _thread_joiner: joiner,
        })
    }

    // TODO: add Service operations like `bootstrap`, `prepare_connection_info`, `connect`, ...
}

impl Drop for Service {
    fn drop(&mut self) {
        // TODO: should we somehow handle Err here?
        let _ = self.sender.send(Message::Shutdown);
    }
}

pub struct Handler {

}

impl Handler {
    fn new() -> Self {
        Handler {

        }
    }
}

impl mio::Handler for Handler {
    type Timeout = Token;
    type Message = Message;

    // fn ready(&mut self, event_loop: &mut EventLoop<Self>,
    //                     token: Token,
    //                     events: EventSet) {

    // }

    // fn notify(&mut self, event_loop: &mut EventLoop<Self>, message: Self::Message) {

    // }

    // fn timeout(&mut self, event_loop: &mut EventLoop<Self>, timeout: Self::Timeout) {

    // }
}
