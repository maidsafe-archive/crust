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

use std::io;
use std::sync::mpsc;

use common::{self, CoreMessage};
use config_file_handler;
use maidsafe_utilities::serialisation::SerialisationError;
use main::PeerId;
use mio;
use nat;
use service_discovery;

quick_error! {
    /// Crust's universal error type.
    #[derive(Debug)]
    pub enum CrustError {
        /// Failed receiving from an mpsc::channel
        ChannelRecv(err: mpsc::RecvError) {
            description("Channel receive error")
            display("Channel receive error: {}", err)
            cause(err)
            from()
        }
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
        /// ServiceDiscovery not enabled yet
        ServiceDiscNotEnabled {
            description("ServiceDiscovery is not yet enabled or registered")
        }
        /// ServiceDiscovery Errors
        ServiceDisc(err: service_discovery::ServiceDiscoveryError) {
            description("ServiceDiscovery error")
            from()
        }
        /// Nat Traversal errors
        Nat(err: nat::NatError) {
            description("Nat Traversal module error")
            from()
        }
        /// Mio Timer errors
        MioTimer(err: mio::TimerError) {
            description("Mio timer error")
            from()
        }
        /// Common module errors
        Common(err: common::CommonError) {
            description("Common module error")
            from()
        }
        /// Mio notify errors
        MioNotify(err: mio::NotifyError<CoreMessage>) {
            description("Mio notify error")
            display("Mio notify error: {}", err)
            cause(err)
            from()
        }
        /// Peer not found
        PeerNotFound(peer_id: PeerId) {
            description("Peer not found")
            display("Peer {:?} not found", peer_id)
        }
        /// Serialisation error
        Serialisation(err: SerialisationError) {
            description("Serialisation error")
            display("Serialisation error: {}", err)
            cause(err)
            from()
        }
    }
}
