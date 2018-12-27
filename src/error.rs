// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::priv_prelude::*;
use config_file_handler;
use notify;
use p2p;

quick_error! {
    /// Crust's universal error type.
    #[derive(Debug)]
    pub enum CrustError {
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
        /// Bootstrapping failed.
        BootstrapFailed {
            description("Bootstrap failed")
        }
        /// The requested peer was not found.
        PeerNotFound {
            description("The requested peer was not found")
        }
        /// Error communicating with a peer.
        PeerError(e: PeerError) {
            description("error raised on a peer")
            display("error raised on a peer: {}", e)
            cause(e)
            from()
        }
        /// Error communicating with a peer at the compat level.
        CompatPeerError(s: String) {
            description("error raised on a compat peer")
            display("error raised on a compat peer: {}", s)
        }
        /// Error receiving data from compatibility layer event loop because it has died.
        CompatEventLoopDied {
            display("Crust compatibility layer event loop died/was destroyed.")
        }
        /// Error starting config file watcher.
        ConfigFileWatcher(e: notify::Error) {
            description("error starting config file watcher")
            display("error starting config file watcher: {}", e)
            cause(e)
            from()
        }
        /// Error starting a listener.
        StartListener(e: io::Error) {
            description("error starting listener")
            display("error starting listener, {}", e)
        }
        /// Error reading bootstrap cache.
        ReadBootstrapCache(e: BootstrapCacheError)  {
            description("Error reading bootstrap cache")
            display("Error reading bootstrap cache: {}", e)
            cause(e)
            from()
        }
        /// Error connecting to peer.
        ConnectError(s: String) {
            description("Failed to connect to peer")
            display("Failed to connect to peer: {}", s)
        }
        /// Failed to prepare our connection information.
        PrepareConnectionInfo {
            description("Failed to prepare our connection info")
        }
        /// Failed to probe NAT type.
        ProbeNatError(e: p2p::RendezvousAddrError) {
            display("Failed to get NAT type: {}", e)
        }
    }
}
