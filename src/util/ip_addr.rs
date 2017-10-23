use priv_prelude::*;

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

