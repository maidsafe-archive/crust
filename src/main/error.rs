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

use common::{self, CoreMessage};
use config_file_handler;
use futures;
use maidsafe_utilities::serialisation::SerialisationError;
use nat;
use notify;
use service_discovery;
use std::io;
use std::sync::mpsc;

quick_error! {
    /// Crust's universal error type.
    #[derive(Debug)]
    pub enum CrustError {
        /// Failed receiving from an mpsc::channel
        ChannelRecv(e: mpsc::RecvError) {
            description("Channel receive error")
            display("Channel receive error: {}", e)
            cause(e)
            from()
        }
        /// Config file handling errors
        ConfigFileHandler(e: config_file_handler::Error) {
            description("Config file handling error")
            display("Config file handling error: {}", e)
            cause(e)
            from()
        }
        /// Wrapper for a `std::io::Error`
        Io(e: io::Error) {
            description("IO error")
            display("IO error: {}", e)
            cause(e)
            from()
        }
        /// ServiceDiscovery not enabled yet
        ServiceDiscNotEnabled {
            description("ServiceDiscovery is not yet enabled or registered")
        }
        /// ServiceDiscovery Errors
        ServiceDisc(e: service_discovery::ServiceDiscoveryError) {
            description("ServiceDiscovery error")
            from()
        }
        /// ServiceDiscovery not enabled yet
        InsufficientConnectionInfo {
            description("Not enough information to initiate connection to peer")
        }
        /// Nat Traversal errors
        Nat(e: nat::NatError) {
            description("Nat Traversal module error")
            from()
        }
        /// Common module errors
        Common(e: common::CommonError) {
            description("Common module error")
            from()
        }
        /// CoreMsg send error
        CoreMsgTx(e: futures::sync::mpsc::SendError<CoreMessage>) {
            description(e.description())
            display("CoreMessage send error: {}", e)
            cause(e)
            from()
        }
        /// Peer not found
        PeerNotFound {
            description("Peer not found")
        }
        /// Serialisation error
        Serialisation(e: SerialisationError) {
            description("Serialisation error")
            display("Serialisation error: {}", e)
            cause(e)
            from()
        }
        /// Requested connect to self
        RequestedConnectToSelf {
            description("Requested connection to self")
            display("Requested connection to self")
        }
        /// Listener is not initialised yet.
        ListenerNotIntialised {
            description("Listener is not initialised yet")
            display("Listener is not initialised yet")
        }
        /// File system notifications error
        Notify(e: notify::Error) {
            description("File system notification error")
            display("File system notification error: {}", e)
            cause(e)
            from()
        }
    }
}
