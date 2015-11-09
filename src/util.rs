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

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, IpAddr, Ipv4Addr, Ipv6Addr};
use std::cmp::Ordering;
use getifaddrs::{getifaddrs, IfAddr};
use ::rustc_serialize::{Encodable, Decodable, Decoder, Encoder};
use transport;
use std::str::FromStr;

#[cfg(test)]
use std::sync::mpsc;
#[cfg(test)]
use std::thread;

////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
/// Utility struct of SocketAddr for hole punching
pub struct SocketAddrW(pub SocketAddr);

impl PartialOrd for SocketAddrW {
    fn partial_cmp(&self, other: &SocketAddrW) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for SocketAddrW {
    fn cmp(&self, other: &SocketAddrW) -> Ordering {
        compare_ip_addrs(&self.0, &other.0)
    }
}

impl Encodable for SocketAddrW {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let as_string = format!("{}", self.0);
        try!(s.emit_str(&as_string[..]));
        Ok(())
    }
}

impl Decodable for SocketAddrW {
    fn decode<D: Decoder>(d: &mut D) -> Result<SocketAddrW, D::Error> {
        let as_string = try!(d.read_str());
        match SocketAddr::from_str(&as_string[..]) {
            Ok(sa)  => Ok(SocketAddrW(sa)),
            Err(e)  => {
                let err = format!("Failed to decode SocketAddrW: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
/// Utility struct of SocketAddrV4 for hole punching
pub struct SocketAddrV4W(pub SocketAddrV4);

impl PartialOrd for SocketAddrV4W {
    fn partial_cmp(&self, other: &SocketAddrV4W) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for SocketAddrV4W {
    fn cmp(&self, other: &SocketAddrV4W) -> Ordering {
        compare_ipv4_addrs(&self.0, &other.0)
    }
}

impl Encodable for SocketAddrV4W {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let as_string = format!("{}", self.0);
        try!(s.emit_str(&as_string[..]));
        Ok(())
    }
}

impl Decodable for SocketAddrV4W {
    fn decode<D: Decoder>(d: &mut D) -> Result<SocketAddrV4W, D::Error> {
        let as_string = try!(d.read_str());
        // TODO: use this code once `impl FromStr for SocketAddrV4` makes it into libstd
        //match SocketAddrV4::from_str(&as_string[..]) {
        //    Ok(sa)  => Ok(SocketAddrV4W(sa)),
        //    Err(e)  => {
        //        let err = format!("Failed to decode SocketAddrV4W: {}", e);
        //        Err(d.error(&err[..]))
        //    }
        //}
        match SocketAddr::from_str(&as_string[..]) {
            Ok(SocketAddr::V4(sa)) => Ok(SocketAddrV4W(sa)),
            Ok(SocketAddr::V6(_sa)) => {
                let err = format!("Failed to decode SocketAddrV4W - Ipv6 address received where ipv4 address expected");
                Err(d.error(&err[..]))
            }
            Err(e)  => {
                let err = format!("Failed to decode SocketAddrV4W: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
pub fn compare_ip_addrs(a1: &SocketAddr, a2: &SocketAddr) -> Ordering {
    use std::net::SocketAddr::{V4,V6};
    match *a1 {
        V4(ref a1) => match *a2 {
            V4(ref a2) => compare_ipv4_addrs(a1, a2),
            V6(_) => Ordering::Less,
        },
        V6(ref a1) => match *a2 {
            V4(_) => Ordering::Greater,
            V6(ref a2) => compare_ipv6_addrs(a1, a2),
        }
    }
}

pub fn compare_ipv4_addrs(a1: &SocketAddrV4, a2: &SocketAddrV4) -> Ordering {
    (a1.ip(), a1.port()).cmp(&(a2.ip(), a2.port()))
}

pub fn compare_ipv6_addrs(a1: &SocketAddrV6, a2: &SocketAddrV6) -> Ordering {
    (a1.ip(), a1.port(), a1.flowinfo(), a1.scope_id())
    .cmp(&(a2.ip(), a2.port(), a2.flowinfo(), a2.scope_id()))
}

////////////////////////////////////////////////////////////////////////////////
pub fn loopback_v4(port: transport::Port) -> transport::Endpoint {
    let ip = IpAddr::V4(Ipv4Addr::new(127,0,0,1));
    transport::Endpoint::new(ip, port)
}

pub fn is_v4(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        &IpAddr::V4(_) => true,
        &IpAddr::V6(_) => false,
    }
}

pub fn is_unspecified(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        &IpAddr::V4(ref ip) => ip.is_unspecified(),
        &IpAddr::V6(ref ip) => ip.is_unspecified(),
    }
}

pub fn is_loopback(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        &IpAddr::V4(ref ip) => ip.is_loopback(),
        &IpAddr::V6(ref ip) => ip.is_loopback(),
    }
}

pub fn is_link_local(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        &IpAddr::V4(ref ip) => ip.is_link_local(),
        &IpAddr::V6(ref _ip) => false, // Not applicable
    }
}

pub fn is_unicast_link_local(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        &IpAddr::V4(ref _ip) => false, // Not applicable
        &IpAddr::V6(ref ip) => ip.is_unicast_link_local(),
    }
}

pub fn is_private(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        &IpAddr::V4(ref ip) => ip.is_private(),
        &IpAddr::V6(ref _ip) => false, // Not applicable
    }
}

pub fn is_unique_local(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        &IpAddr::V4(ref _ip) => false, // Not applicable
        &IpAddr::V6(ref ip) => ip.is_unique_local(),
    }
}

pub fn on_same_subnet_v4( ip_addr1: Ipv4Addr
                        , ip_addr2: Ipv4Addr
                        , netmask:  Ipv4Addr) -> bool {
    let o1 = ip_addr1.octets();
    let o2 = ip_addr2.octets();
    let m  = netmask.octets();

    for i in 0..4 {
        if o1[i] & m[i] != o2[i] & m[i] {
            return false;
        }
    }

    return true;
}

pub fn on_same_subnet_v6( ip_addr1: Ipv6Addr
                        , ip_addr2: Ipv6Addr
                        , netmask:  Ipv6Addr) -> bool {
    let s1 = ip_addr1.segments();
    let s2 = ip_addr2.segments();
    let m  = netmask.segments();

    for i in 0..8 {
        if s1[i] & m[i] != s2[i] & m[i] {
            return false;
        }
    }

    return true;
}

pub fn on_same_subnet(ip_addr1: IpAddr,
                      ip_addr2: IpAddr,
                      netmask:  IpAddr) -> bool {
    use ::std::net::IpAddr::V4;
    use ::std::net::IpAddr::V6;

    match (ip_addr1, ip_addr2, netmask) {
        (V4(ip1), V4(ip2), V4(m)) => {
            on_same_subnet_v4(ip1, ip2, m)
        },
        (V6(ip1), V6(ip2), V6(m)) => {
            on_same_subnet_v6(ip1, ip2, m)
        },
        _ => {
            false
        }
    }
}

pub fn is_local(ip_addr: &IpAddr, interfaces: &Vec<IfAddr>) -> bool {
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
    use ::std::cmp::Ordering::{Less, Equal, Greater};

    if ip1 == ip2 { return Equal; }

    match (is_unspecified(ip1), is_unspecified(ip2)) {
        (true, true)  => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    match (is_loopback(ip1), is_loopback(ip2)) {
        (true, true)  => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    match (is_link_local(ip1), is_link_local(ip2)) {
        (true, true)  => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    match (is_unicast_link_local(ip1), is_unicast_link_local(ip2)) {
        (true, true)  => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    match (is_private(ip1), is_private(ip2)) {
        (true, true)  => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    match (is_unique_local(ip1), is_unique_local(ip2)) {
        (true, true)  => return Equal,
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => (),
    }

    let interfaces = getifaddrs();

    match (is_local(ip1, &interfaces), is_local(ip2, &interfaces)) {
        (true, true)   => return Equal,
        (true, false)  => return Less,
        (false, true)  => return Greater,
        (false, false) => return Equal,
    }
}

/// This function should really take IpAddr as an argument
/// but it is used outside of this library and IpAddr
/// is currently considered experimental.
pub fn ifaddrs_if_unspecified(ep: transport::Endpoint) -> Vec<transport::Endpoint> {
    if !is_unspecified(&ep.get_address().ip()) {
        return vec![ep];
    }

    let ep_is_v4 = is_v4(&ep.get_address().ip());

    getifaddrs().into_iter()
        .filter_map(|iface| {
            if ep_is_v4 != is_v4(&iface.addr) { return None; }
            Some(transport::Endpoint::new(iface.addr, ep.get_port()))
        })
        .collect()
}

#[cfg(test)]
pub fn loopback_if_unspecified(addr : IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => {
            IpAddr::V4(if addr.is_unspecified() {
                           Ipv4Addr::new(127,0,0,1)
                       } else {
                           addr
                       })
        },
        IpAddr::V6(addr) => {
            IpAddr::V6(if addr.is_unspecified() {
                           "::1".parse().unwrap()
                       } else {
                           addr
                       })
        }
    }
}

#[cfg(test)]
pub fn random_endpoint() -> ::transport::Endpoint {
    // TODO - randomise V4/V6 and TCP/UTP
    let address = ::std::net::SocketAddrV4::new(
        ::std::net::Ipv4Addr::new(::rand::random::<u8>(),
                                  ::rand::random::<u8>(),
                                  ::rand::random::<u8>(),
                                  ::rand::random::<u8>()),
        ::rand::random::<u16>());
    ::transport::Endpoint::Tcp(::std::net::SocketAddr::V4(address))
}

#[cfg(test)]
pub fn random_endpoints(count: usize) -> Vec<::transport::Endpoint> {
    let mut contacts = Vec::new();
    for _ in 0..count {
        contacts.push(random_endpoint());
    }
    contacts
}

#[cfg(test)]
pub fn random_global_endpoint() -> ::transport::Endpoint {
    // TODO - randomise V4/V6 and TCP/UTP
    let address = ::std::net::SocketAddrV4::new(
        ::std::net::Ipv4Addr::new(173, // ensure is a global addr
                                  ::rand::random::<u8>(),
                                  ::rand::random::<u8>(),
                                  ::rand::random::<u8>()),
        ::rand::random::<u16>());
    ::transport::Endpoint::Tcp(::std::net::SocketAddr::V4(address))
}

#[cfg(test)]
pub fn random_global_endpoints(count: usize) -> Vec<::transport::Endpoint> {
    let mut contacts = Vec::new();
    for _ in 0..count {
        contacts.push(random_global_endpoint());
    }
    contacts
}

#[cfg(test)]
pub fn timed_recv<T>(receiver: &mpsc::Receiver<T>, timeout: ::std::time::Duration)
                     -> Result<T, mpsc::TryRecvError>
{
    let step = ::std::time::Duration::from_millis(20);
    let mut time = ::std::time::Duration::new(0, 0);
    loop {
        match receiver.try_recv() {
            Ok(v) => return Ok(v),
            Err(what) => match what {
                mpsc::TryRecvError::Empty => {
                    if time >= timeout {
                        return Err(what);
                    }
                },
                mpsc::TryRecvError::Disconnected => {
                    return Err(what);
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
        use getifaddrs::getifaddrs;
        use ::std::cmp::Ordering::{Less, Equal, Greater};
        use ::std::net::Ipv4Addr;
        use ::std::net::IpAddr::V4;

        let g = V4(Ipv4Addr::new(173,194,116,137));
        let l = V4(Ipv4Addr::new(127,0,0,1));

        assert_eq!(super::heuristic_geo_cmp(&l, &l), Equal);
        assert_eq!(super::heuristic_geo_cmp(&l, &l), Equal);

        assert_eq!(super::heuristic_geo_cmp(&l, &g), Less);
        assert_eq!(super::heuristic_geo_cmp(&g, &l), Greater);

        let ifs = getifaddrs().into_iter()
            .map(|interface| interface.addr)
            .filter(|addr| !super::is_loopback(&addr))
            .collect::<Vec<_>>();

        for i in ifs {
            assert_eq!(super::heuristic_geo_cmp(&i, &l), Greater);
            assert_eq!(super::heuristic_geo_cmp(&i, &g), Less);
        }
    }
}
