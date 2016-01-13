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
use get_if_addrs::{getifaddrs, IfAddr};
use endpoint::Endpoint;
use std::net;
use ip_info;

#[cfg(test)]
use std::sync::mpsc;
#[cfg(test)]
use std::thread;
#[cfg(test)]
use endpoint::Protocol;
#[cfg(test)]
use socket_addr::SocketAddr;

/// /////////////////////////////////////////////////////////////////////////////
// pub fn loopback_v4(port: Port) -> IpAddrV4 {
//    net::Ipv4Addr::new(127, 0, 0, 1)
//}

pub fn is_v4(ip_addr: &IpAddr) -> bool {
    match *ip_addr {
        IpAddr::V4(_) => true,
        IpAddr::V6(_) => false,
    }
}

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

pub fn on_same_subnet(ip_addr1: IpAddr, ip_addr2: IpAddr, netmask: IpAddr) -> bool {
    use ip::IpAddr::V4;
    use ip::IpAddr::V6;

    match (ip_addr1, ip_addr2, netmask) {
        (V4(ip1), V4(ip2), V4(m)) => on_same_subnet_v4(ip1, ip2, m),
        (V6(ip1), V6(ip2), V6(m)) => on_same_subnet_v6(ip1, ip2, m),
        _ => false,
    }
}

pub fn is_local(ip_addr: &IpAddr, interfaces: &[IfAddr]) -> bool {
    for i in interfaces.iter() {
        if on_same_subnet(i.addr, *ip_addr, i.netmask) {
            return true;
        }
    }
    false
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

    let interfaces = getifaddrs();

    match (is_local(ip1, &interfaces), is_local(ip2, &interfaces)) {
        (true, true) => Equal,
        (true, false) => Less,
        (false, true) => Greater,
        (false, false) => Equal,
    }
}

/// TODO This function should really take IpAddr as an argument
/// but it is used outside of this library and IpAddr
/// is currently considered experimental.
pub fn ifaddrs_if_unspecified(ep: &Endpoint) -> Vec<Endpoint> {
    match ep.ip() {
        IpAddr::V4(ref addr) => {
            if !::ip_info::v4::is_unspecified(addr) {
                return vec![ep.clone()];
            }
        }
        IpAddr::V6(ref addr) => {
            if !::ip_info::v6::is_unspecified(addr) {
                return vec![ep.clone()];
            }
        }
    }

    let ep_is_v4 = is_v4(&ep.ip());

    getifaddrs()
        .into_iter()
        .filter_map(|iface| {
            if ep_is_v4 != is_v4(&iface.addr) {
                return None;
            }
            Some(Endpoint::new(ep.protocol().clone(), iface.addr, ep.port()))
        })
        .collect()
}

#[cfg(test)]
pub fn loopback_if_unspecified(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => {
            IpAddr::V4(if ::ip_info::v4::is_unspecified(&addr) {
                net::Ipv4Addr::new(127, 0, 0, 1)
            } else {
                addr
            })
        }
        IpAddr::V6(addr) => {
            IpAddr::V6(if ::ip_info::v6::is_unspecified(&addr) {
                "::1".parse().unwrap()
            } else {
                addr
            })
        }
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
    #[test]
    fn test_heuristic_geo_cmp() {
        use get_if_addrs::getifaddrs;
        use std::cmp::Ordering::{Less, Equal, Greater};
        use ip::IpAddr::V4;

        let g = V4(::std::net::Ipv4Addr::new(173, 194, 116, 137));
        let l = V4(::std::net::Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(super::heuristic_geo_cmp(&l, &l), Equal);
        assert_eq!(super::heuristic_geo_cmp(&l, &l), Equal);

        assert_eq!(super::heuristic_geo_cmp(&l, &g), Less);
        assert_eq!(super::heuristic_geo_cmp(&g, &l), Greater);

        let ifs = getifaddrs()
                      .into_iter()
                      .map(|interface| interface.addr)
                      .filter(|addr| !super::is_loopback(&addr))
                      .collect::<Vec<_>>();

        for i in ifs {
            assert_eq!(super::heuristic_geo_cmp(&i, &l), Greater);
            assert_eq!(super::heuristic_geo_cmp(&i, &g), Less);
        }
    }
}
