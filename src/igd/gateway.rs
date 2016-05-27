use std::net::{Ipv4Addr, SocketAddrV4};
use core::Core;
use igd::errors::{AddAnyPortError, GetExternalIpError};
use mio::EventLoop;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[allow(unused)]
/// This structure represents a gateway found by the search functions.
pub struct Gateway {
    /// Socket address of the gateway
    pub addr: SocketAddrV4,
    /// Control url of the device
    pub control_url: String,
}

impl Gateway {
    #[allow(unused)]
    pub fn get_external_ip<F>(core: &mut Core,
                              event_loop: &mut EventLoop<Core>,
                              callback: F)
        where F: FnOnce(Result<Ipv4Addr, GetExternalIpError>, &mut Core,
                        &mut EventLoop<Core>) + 'static {
        unimplemented!();
    }

    #[allow(unused)]
    pub fn add_any_port<F>(core: &mut Core,
                           event_loop: &mut EventLoop<Core>,
                           callback: F)
        where F: FnOnce(Result<u16, AddAnyPortError>) + 'static {
        unimplemented!();
    }
}
