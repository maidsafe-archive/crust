// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use maidsafe_utilities::serialisation::SerialisationError;
use std::io;
use std::net::AddrParseError;

quick_error! {
    #[derive(Debug)]
    pub enum ServiceDiscoveryError {
        Io(e: io::Error) {
            description("Io error during service discovery")
            display("Io error during service discovery: {}", e)
            from()
        }
        AddrParse(e: AddrParseError) {
            description("Error parsing address for service discovery")
            display("Error parsing address for service discovery: {}", e)
            from()
        }
        Serialisation(e: SerialisationError) {
            description("Serialisation error during service discovery")
            display("Serialisation error during service discovery: {}", e)
            from()
        }
    }
}
