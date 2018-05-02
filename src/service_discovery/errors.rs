// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

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
