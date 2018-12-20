// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::CommonError;
use socket_collection::SocketError;
use std::io;

quick_error! {
    /// Nat Traversal specific error
    #[derive(Debug)]
    pub enum NatError {
        /// IO error
        Io(e: io::Error) {
            description("Io error during nat traversal")
            display("Io error during nat traversal: {}", e)
            cause(e)
            from()
        }
        /// Common error
        CommonError(e: CommonError) {
            description(e.description())
            display("NatError: {}", e)
            cause(e)
            from()
        }
        /// `socket-collection` error
        SocketError(e: SocketError) {
            display("Socket error: {}", e)
            cause(e)
            from()
        }
    }
}
