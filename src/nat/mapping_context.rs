//! Defines the MappingContext type

use std::net::SocketAddr;
use std::slice;

/// Keeps track of information about external mapping servers
pub struct MappingContext {
    tcp_mapping_servers: Vec<SocketAddr>,
}

impl MappingContext {
    /// Create a new MappingContext
    pub fn new() -> MappingContext {
        MappingContext { tcp_mapping_servers: Vec::new() }
    }

    /// Inform the context about external servers
    pub fn add_tcp_mapping_servers<S>(&mut self, servers: S)
        where S: IntoIterator<Item = SocketAddr>
    {
        self.tcp_mapping_servers.extend(servers)
    }

    /// Iterate over the known servers
    pub fn tcp_mapping_servers<'m>(&'m self) -> IterTcpMappingServers<'m> {
        self.tcp_mapping_servers.iter()
    }
}

/// Iterator returned by MappingContext::tcp_mapping_servers
pub type IterTcpMappingServers<'m> = slice::Iter<'m, SocketAddr>;
