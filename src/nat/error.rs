// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use common::CommonError;
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
    }
}
