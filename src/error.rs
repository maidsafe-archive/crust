// Copyright 2017 MaidSafe.net limited.
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

use config_file_handler;
use notify;
use priv_prelude::*;

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
    }
}
