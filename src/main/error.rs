// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::nat;
use crate::{common, service_discovery};
use config_file_handler;
use maidsafe_utilities::serialisation::SerialisationError;
use safe_crypto;
use socket_collection::SocketError;
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
        /// CoreMessage send error
        CoreMsgTx {
            display("CoreMessage channel was destroyed")
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
        /// `socket-collection` error
        SocketError(e: SocketError) {
            display("Socket error: {}", e)
            cause(e)
            from()
        }
        /// Crypto error.
        Crypto(e: safe_crypto::Error) {
            display("Crypto error: {}", e)
            cause(e)
            from()
        }
    }
}
