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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{mem, str};
use std::ffi::CStr;
use libc::consts::os::bsd44::{AF_INET, AF_INET6};
use libc::funcs::bsd43::getifaddrs as posix_getifaddrs;
use libc::funcs::bsd43::freeifaddrs as posix_freeifaddrs;
use libc::types::os::common::bsd44::ifaddrs as posix_ifaddrs;
use libc::types::os::common::bsd44::sockaddr as posix_sockaddr;

/// Details about an interface on this host
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct IfAddr {
    /// The name of the interface
    pub name: String,
    /// The IP address of the interface
    pub addr: IpAddr,
    /// The netmask of the interface
    pub netmask: IpAddr,
    /// How to send a broadcast on the interface
    pub broadcast: IpAddr,
}

impl IfAddr {
    /// Create a new IfAddr
    pub fn new() -> IfAddr {
        IfAddr {
            name: String::new(),
            addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            netmask: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            broadcast: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        }
    }
}

/// Return a vector of IP details for all the valid interfaces on this host
#[allow(unsafe_code)]
pub fn getifaddrs() -> Vec<IfAddr> {
    let mut ret = Vec::<IfAddr>::new();
    unsafe {
      let mut ifaddrs : *mut posix_ifaddrs = mem::uninitialized();
      if -1 == posix_getifaddrs(&mut ifaddrs) {
        panic!("failed to retrieve interface details from getifaddrs()");
      }
      let sockaddr_to_ipaddr = |sockaddr : posix_sockaddr| -> Option<IpAddr> {
          if sockaddr.sa_family == AF_INET as u16 {
              Some(IpAddr::V4(Ipv4Addr::new(
                  sockaddr.sa_data[0],
                  sockaddr.sa_data[1],
                  sockaddr.sa_data[2],
                  sockaddr.sa_data[3],
              )))
          } else if sockaddr.sa_family == AF_INET6 as u16 {
              Some(IpAddr::V6(Ipv6Addr::new(
                  sockaddr.sa_data[0] as u16  | ((sockaddr.sa_data[1] as u16) << 8),
                  sockaddr.sa_data[2] as u16  | ((sockaddr.sa_data[3] as u16) << 8),
                  sockaddr.sa_data[4] as u16  | ((sockaddr.sa_data[5] as u16) << 8),
                  sockaddr.sa_data[6] as u16  | ((sockaddr.sa_data[7] as u16) << 8),
                  sockaddr.sa_data[8] as u16  | ((sockaddr.sa_data[9] as u16) << 8),
                  sockaddr.sa_data[10] as u16 | ((sockaddr.sa_data[11] as u16) << 8),
                  sockaddr.sa_data[12] as u16 | ((sockaddr.sa_data[13] as u16) << 8),
                  sockaddr.sa_data[14] as u16 | ((sockaddr.sa_data[15] as u16) << 8),
              )))
          }
          else { None }
      };
          
      let mut ifaddr = ifaddrs;
      while !ifaddr.is_null() {
          if (*ifaddr).ifa_addr.is_null() {
              continue;
          }
          let mut item = IfAddr::new();
          let name = CStr::from_ptr((*ifaddr).ifa_name).to_bytes();
          item.name = str::from_utf8(name).unwrap().to_owned();
          match sockaddr_to_ipaddr(*(*ifaddr).ifa_addr) {
              Some(a) => item.addr = a,
              None => continue,
          };
          match sockaddr_to_ipaddr(*(*ifaddr).ifa_netmask) {
              Some(a) => item.netmask = a,
              None => continue,
          };
          if ((*ifaddr).ifa_flags & 2 /*IFF_BROADCAST*/) != 0 {
              match sockaddr_to_ipaddr(*(*ifaddr).ifa_ifu) {
                  Some(a) => item.broadcast = a,
                  None => continue,
              };
          }
          ret.push(item);
          ifaddr = (*ifaddr).ifa_next;
      }
      posix_freeifaddrs(ifaddrs);
    }
    ret
}

#[cfg(test)]
mod test {
    use super::getifaddrs;
    use std::net::IpAddr;
    
    #[test]
    fn test_getifaddrs() {
        let mut has_loopback4 = false;
        let mut has_loopback6 = false;
        for ifaddr in getifaddrs() {
            println!("Interface {} has IP {} netmask {} broadcast {}", ifaddr.name,
                     ifaddr.addr, ifaddr.netmask, ifaddr.broadcast);
            match ifaddr.addr {
                IpAddr::V4(v4) => if v4.is_loopback() { has_loopback4=true; },
                IpAddr::V6(v6) => if v6.is_loopback() { has_loopback6=true; },
            }
        }
        // Quick sanity test, can't think of anything better
        assert_eq!(has_loopback4 || has_loopback6, true);
    }
}
