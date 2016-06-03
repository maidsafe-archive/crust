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

use peer_id::PeerId;
use core::CoreMessage;
use service_discovery;
use config_file_handler;
use maidsafe_utilities::serialisation::SerialisationError;

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
        /// Mio Timer errors
        MioTimer(err: mio::TimerError) {
            description("Mio timer error")
            from()
        }
        /// Size of a message to send is too large
        PayloadSizeProhibitive {
            description("Payload is too large")
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

impl From<CrustError> for io::Error {
    fn from(err: CrustError) -> io::Error {
        match err {
            CrustError::Io(e) => e,
            CrustError::MioNotify(e) => match e {
                mio::NotifyError::Io(e) => e,
                mio::NotifyError::Full(..)
                    => io::Error::new(io::ErrorKind::Other, "Mio notify error \
                                                             (channel full)"),
                mio::NotifyError::Closed(..)
                    => io::Error::new(io::ErrorKind::Other, "Mio notify error \
                                                             (channel closed)"),
            },
            CrustError::ChannelRecv(e)
                => io::Error::new(io::ErrorKind::Other, e),
            CrustError::ConfigFileHandler(e)
                => io::Error::new(io::ErrorKind::Other, e),
            CrustError::ServiceDiscNotEnabled
                => io::Error::new(io::ErrorKind::Other, "Service discovery not \
                                                         enabled"),
            CrustError::ServiceDisc(e)
                => io::Error::new(io::ErrorKind::Other, e),
            CrustError::MioTimer(e)
                => io::Error::new(io::ErrorKind::Other, format!("Mio timer \
                                                                 error: {:?}",
                                                                 e)),
            CrustError::PayloadSizeProhibitive
                => io::Error::new(io::ErrorKind::Other, "Payload size \
                                                         prohibitive"),
            CrustError::PeerNotFound(peer_id)
                => io::Error::new(io::ErrorKind::Other, format!("Peer not \
                                                                 found: {:?}",
                                                                 peer_id)),
            CrustError::Serialisation(e)
                => io::Error::new(io::ErrorKind::Other, e),
        }
    }
}

