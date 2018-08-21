// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use net2::TcpBuilder;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub fn new_reusably_bound_tcp_socket(local_addr: &SocketAddr) -> io::Result<TcpBuilder> {
    let socket = match local_addr.ip() {
        IpAddr::V4(..) => TcpBuilder::new_v4()?,
        IpAddr::V6(..) => TcpBuilder::new_v6()?,
    };
    let _ = socket.reuse_address(true)?;
    enable_so_reuseport(&socket)?;
    let _ = socket.bind(local_addr)?;

    Ok(socket)
}

#[cfg(target_family = "unix")]
pub fn enable_so_reuseport(sock: &TcpBuilder) -> io::Result<()> {
    use net2::unix::UnixTcpBuilderExt;
    let _ = sock.reuse_port(true)?;
    Ok(())
}

#[cfg(target_family = "windows")]
pub fn enable_so_reuseport(_sock: &TcpBuilder) -> io::Result<()> {
    Ok(())
}

/// A replacement for `IpAddr::is_global` while we wait for that to enter stable.
pub fn ip_addr_is_global(ip: &IpAddr) -> bool {
    match *ip {
        IpAddr::V4(addr_v4) => ipv4_addr_is_global(addr_v4),
        IpAddr::V6(addr_v6) => ipv6_addr_is_global(addr_v6),
    }
}

/// A replacement for `Ipv4Addr::is_global` while we wait for that to enter stable.
pub fn ipv4_addr_is_global(ipv4: Ipv4Addr) -> bool {
    !(ipv4.is_loopback()
        || ipv4.is_private()
        || ipv4.is_link_local()
        || ipv4.is_multicast()
        || ipv4.is_broadcast()
        || ipv4.is_documentation()
        || ipv4.octets() == [0, 0, 0, 0])
}

/// A replacement for `Ipv6Addr::is_global` while we wait for that to enter stable.
pub fn ipv6_addr_is_global(ipv6: Ipv6Addr) -> bool {
    // TODO(canndrew): This function is incomplete and may return false-positives.
    !(ipv6.is_loopback() || ipv6.is_unspecified())
}
