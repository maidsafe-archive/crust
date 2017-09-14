// Copyright 2016 MaidSafe.net limited.
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

use common::CoreMessage;
use futures;
use maidsafe_utilities::serialisation::SerialisationError;
use mio::timer::TimerError;
use std::io;

quick_error! {
    /// Common module specific error
    #[derive(Debug)]
    pub enum CommonError {
        /// IO error
        Io(e: io::Error) {
            description(e.description())
            display("Io error: {}", e)
            cause(e)
            from()
        }
        /// Socket is uninitialised and invalid for any operation
        UninitialisedSocket {
            description("Socket is uninitialised and invalid for any operation")
            display("Socket is uninitialised and invalid for any operation")
        }
        /// Size of a message to send or about to be read is too large
        PayloadSizeProhibitive {
            description("Payload is too large")
        }
        /// Serialisation error
        Serialisation(e: SerialisationError) {
            description(e.description())
            display("Serialisation error: {}", e)
            cause(e)
            from()
        }
        /// Timer error
        Timer(e: TimerError) {
            description(e.description())
            display("Timer error: {}", e)
            cause(e)
            from()
        }
        /// A zero byte socket read - means EOF
        ZeroByteRead {
            description("Read zero bytes from the socket - indicates EOF")
        }
        /// CoreMessage send error
        CoreMsgTx(e: futures::sync::mpsc::SendError<CoreMessage>) {
            description(e.description())
            display("CoreMessage send error: {}", e)
            cause(e)
            from()
        }
    }
}
