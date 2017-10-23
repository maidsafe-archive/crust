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

use igd;
use priv_prelude::*;

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
        /// IGD error
        IgdAddAnyPort(e: igd::AddAnyPortError) {
            description("Error requesting port from IGD gateway")
            display("Error requesting port from IGD gateway: {}", e)
            cause(e)
            from()
        }
    }
}
