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
        IpAddr::V4(ref addr_v4) => ipv4_addr_is_global(addr_v4),
        IpAddr::V6(ref addr_v6) => ipv6_addr_is_global(addr_v6),
    }
}

/// A replacement for `Ipv4Addr::is_global` while we wait for that to enter stable.
pub fn ipv4_addr_is_global(ipv4: &Ipv4Addr) -> bool {
    !(ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local() ||
      ipv4.is_multicast() || ipv4.is_broadcast() || ipv4.is_documentation() ||
      ipv4.octets() == [0, 0, 0, 0])
}

/// A replacement for `Ipv6Addr::is_global` while we wait for that to enter stable.
pub fn ipv6_addr_is_global(ipv6: &Ipv6Addr) -> bool {
    // TODO(canndrew): This function is incomplete and may return false-positives.
    !(ipv6.is_loopback() || ipv6.is_unspecified())
}
