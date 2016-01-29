// Copyright 2015 MaidSafe.net limited.
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

use ip::IpAddr;
use std::cmp::Ordering;
use get_if_addrs::{get_if_addrs, Interface, IfAddr};
use std::net;
use ip_info;

#[cfg(test)]
use std::sync::mpsc;
#[cfg(test)]
use std::thread;
#[cfg(test)]
use endpoint::{Protocol, Endpoint};
#[cfg(test)]
use socket_addr::SocketAddr;

/// /////////////////////////////////////////////////////////////////////////////
pub fn is_global(ip: &IpAddr) -> bool {
    match *ip {
        IpAddr::V4(ref ipv4) => ip_info::v4::is_global(ipv4),
        IpAddr::V6(ref ipv6) => ip_info::v6::is_global(ipv6),
    }
}

pub fn is_unspecified(ip_addr: &IpAddr) -> bool {
    match *ip_addr {
        IpAddr::V4(ref ip) => ::ip_info::v4::is_unspecified(ip),
        IpAddr::V6(ref ip) => ::ip_info::v6::is_unspecified(ip),
    }
}

pub fn is_loopback(ip_addr: &IpAddr) -> bool {
    match *ip_addr {
        IpAddr::V4(ref ip) => ::ip_info::v4::is_loopback(ip),
        IpAddr::V6(ref ip) => ::ip_info::v6::is_loopback(ip),
    }
}

pub fn is_link_local(ip_addr: &IpAddr) -> bool {
    match *ip_addr {
        IpAddr::V4(ref ip) => ::ip_info::v4::is_link_local(ip),
        IpAddr::V6(ref _ip) => false, // Not applicable
    }
}

pub fn is_unicast_link_local(ip_addr: &IpAddr) -> bool {
    match *ip_addr {
        IpAddr::V4(ref _ip) => false, // Not applicable
        IpAddr::V6(ref ip) => ::ip_info::v6::is_unicast_link_local(ip),
    }
}

pub fn is_private(ip_addr: &IpAddr) -> bool {
    match *ip_addr {
        IpAddr::V4(ref ip) => ::ip_info::v4::is_private(ip),
        IpAddr::V6(ref _ip) => false, // Not applicable
    }
}

pub fn is_unique_local(ip_addr: &IpAddr) -> bool {
    match *ip_addr {
        IpAddr::V4(ref _ip) => false, // Not applicable
        IpAddr::V6(ref ip) => ::ip_info::v6::is_unique_local(ip),
    }
}

pub fn on_same_subnet_v4(ip_addr1: net::Ipv4Addr,
                         ip_addr2: net::Ipv4Addr,
                         netmask: net::Ipv4Addr)
                         -> bool {
    let o1 = ip_addr1.octets();
    let o2 = ip_addr2.octets();
    let m = netmask.octets();

    for i in 0..4 {
        if o1[i] & m[i] != o2[i] & m[i] {
            return false;
        }
    }

    true
}

pub fn on_same_subnet_v6(ip_addr1: net::Ipv6Addr,
                         ip_addr2: net::Ipv6Addr,
                         netmask: net::Ipv6Addr)
                         -> bool {
    let s1 = ip_addr1.segments();
    let s2 = ip_addr2.segments();
    let m = netmask.segments();

    for i in 0..8 {
        if s1[i] & m[i] != s2[i] & m[i] {
            return false;
        }
    }

    true
}

pub fn is_local(ip_addr: &IpAddr, interfaces: &[Interface]) -> bool {
    for i in interfaces.iter() {
        match (*ip_addr, &i.addr) {
            (IpAddr::V4(ipv4_addr), &IfAddr::V4(ref ifv4_addr)) => {
                if on_same_subnet_v4(ipv4_addr, ifv4_addr.ip, ifv4_addr.netmask) {
                    return true;
                }
            }
            (IpAddr::V6(ipv6_addr), &IfAddr::V6(ref ifv6_addr)) => {
                if on_same_subnet_v6(ipv6_addr, ifv6_addr.ip, ifv6_addr.netmask) {
                    return true;
                }
            }
            _ => (),
        }
    }
    false
}

fn ip(addr: &net::SocketAddr) -> IpAddr {
    match *addr {
        net::SocketAddr::V4(ref addr) => IpAddr::V4(*addr.ip()),
        net::SocketAddr::V6(ref addr) => IpAddr::V6(*addr.ip()),
    }
}

/// If the endpoint IP address is unspecified return a copy of the endpoint with the IP address
/// set to the loopback address. Otherwise return a copy of the endpoint.
pub fn unspecified_to_loopback(addr: &net::SocketAddr) -> net::SocketAddr {
    if is_unspecified(&ip(addr)) {
        match *addr {
            net::SocketAddr::V4(ref addr) => {
                let ip_addr = net::Ipv4Addr::new(127, 0, 0, 1);
                net::SocketAddr::V4(net::SocketAddrV4::new(ip_addr, addr.port()))
            }
            net::SocketAddr::V6(ref addr) => {
                let ip_addr = net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
                net::SocketAddr::V6(net::SocketAddrV6::new(ip_addr,
                                                           addr.port(),
                                                           addr.flowinfo(),
                                                           addr.scope_id()))
            }
        }
    } else {
        *addr
    }
}

/// Use heuristic to determine which IP is closer to us
/// geographically. That is, ip1 is closer to us than ip2 => ip1 < ip2.
#[allow(dead_code)]
pub fn heuristic_geo_cmp(ip1: &IpAddr, ip2: &IpAddr) -> Ordering {
    use std::cmp::Ordering::{Less, Equal, Greater};

    if ip1 == ip2 {
        return Equal;
    }

    match (is_unspecified(ip1), is_unspecified(ip2)) {
        (true, true) => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    match (is_loopback(ip1), is_loopback(ip2)) {
        (true, true) => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    match (is_link_local(ip1), is_link_local(ip2)) {
        (true, true) => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    match (is_unicast_link_local(ip1), is_unicast_link_local(ip2)) {
        (true, true) => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    match (is_private(ip1), is_private(ip2)) {
        (true, true) => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    match (is_unique_local(ip1), is_unique_local(ip2)) {
        (true, true) => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    let interfaces = match get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(_) => return Equal,
    };

    match (is_local(ip1, &interfaces), is_local(ip2, &interfaces)) {
        (true, true) => Equal,
        (true, false) => Less,
        (false, true) => Greater,
        (false, false) => Equal,
    }
}


#[cfg(test)]
pub fn random_endpoint() -> Endpoint {
    // TODO - randomise V4/V6 and TCP/UTP
    let address = net::SocketAddrV4::new(net::Ipv4Addr::new(::rand::random::<u8>(),
                                                            ::rand::random::<u8>(),
                                                            ::rand::random::<u8>(),
                                                            ::rand::random::<u8>()),
                                         ::rand::random::<u16>());
    Endpoint::from_socket_addr(Protocol::Tcp, SocketAddr(net::SocketAddr::V4(address)))
}


#[cfg(test)]
pub fn timed_recv<T>(receiver: &mpsc::Receiver<T>,
                     timeout: ::std::time::Duration)
                     -> Result<T, mpsc::TryRecvError> {
    let step = ::std::time::Duration::from_millis(20);
    let mut time = ::std::time::Duration::new(0, 0);
    loop {
        match receiver.try_recv() {
            Ok(v) => return Ok(v),
            Err(what) => {
                match what {
                    mpsc::TryRecvError::Empty => {
                        if time >= timeout {
                            return Err(what);
                        }
                    }
                    mpsc::TryRecvError::Disconnected => {
                        return Err(what);
                    }
                }
            }
        }
        thread::sleep(step);
        time = time + step;
    }
}

#[cfg(test)]
mod test {
    use get_if_addrs::get_if_addrs;

    #[test]
    fn test_heuristic_geo_cmp() {
        use std::cmp::Ordering::{Less, Equal, Greater};
        use ip::IpAddr::V4;

        let g = V4(::std::net::Ipv4Addr::new(173, 194, 116, 137));
        let l = V4(::std::net::Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(super::heuristic_geo_cmp(&l, &l), Equal);
        assert_eq!(super::heuristic_geo_cmp(&l, &l), Equal);

        assert_eq!(super::heuristic_geo_cmp(&l, &g), Less);
        assert_eq!(super::heuristic_geo_cmp(&g, &l), Greater);

        let ifs = unwrap_result!(get_if_addrs())
                      .into_iter()
                      .filter(|iface| !iface.is_loopback())
                      .map(|iface| iface.ip())
                      .collect::<Vec<_>>();

        for i in ifs {
            assert_eq!(super::heuristic_geo_cmp(&i, &l), Greater);
            assert_eq!(super::heuristic_geo_cmp(&i, &g), Less);
        }
    }
}
