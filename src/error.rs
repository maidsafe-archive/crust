use notify;
use config_file_handler;
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
        /// Error from the NAT module.
        NatError(e: NatError) {
            description("Error from NAT library")
            display("Error from NAT library: {}", e)
            from()
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
        /// Error starting config file watcher.
        ConfigFileWatcher(e: notify::Error) {
            description("error starting config file watcher")
            display("error starting config file watcher: {}", e)
            cause(e)
            from()
        }
        /// Error preparing connection info.
        PrepareConnectionInfo(e: io::Error) {
            description("error preparing connection info")
            display("error preparing connection info. {}", e)
        }
        /// Error starting a listener.
        StartListener(e: io::Error) {
            description("error starting listener")
            display("error starting listener, {}", e)
        }
    }
}

