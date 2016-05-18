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

use mio;
use std::io;
use std::sync::mpsc;
use config_file_handler;

use core::CoreMessage;

quick_error! {
    /// Crust's universal error type.
    #[derive(Debug)]
    pub enum Error {
        /// Config file handling errors
        ConfigFileHandler(err: config_file_handler::Error) {
            description("Config file handling error")
            display("Config file handling error: {}", err)
            cause(err)
            from()
        }

        /// Wrapper for a `std::io::Error`
        Io(err: io::Error) {
            description("IO error")
            display("IO error: {}", err)
            cause(err)
            from()
        }

        /// Mio notify errors
        MioNotify(err: mio::NotifyError<CoreMessage>) {
            description("Mio notify error")
            display("Mio notify error: {}", err)
            cause(err)
            from()
        }

        /// Failed receiving from a channel
        RecvError(err: mpsc::RecvError) {
            description("Channel receive error")
            display("Channel receive error: {}", err)
            cause(err)
            from()
        }

        /// Size of a message to send is too large
        MessageTooLarge {
            description("Message too large")
        }
    }
}
