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

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(test)]
use std::net::IpAddr;

/// Details about an interface on this host
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Interface {
    /// The name of the interface.
    pub name: String,
    /// The address details of the interface.
    pub addr: IfAddr,
}

/// Details about the address of an interface on this host
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum IfAddr {
    /// This is an Ipv4 interface.
    V4(Ifv4Addr),
    /// This is an Ipv6 interface.
    V6(Ifv6Addr),
}

/// Details about the ipv4 address of an interface on this host
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Ifv4Addr {
    /// The IP address of the interface.
    pub ip: Ipv4Addr,
    /// The netmask of the interface.
    pub netmask: Ipv4Addr,
    /// The broadcast address of the interface.
    pub broadcast: Option<Ipv4Addr>,
}

/// Details about the ipv6 address of an interface on this host
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Ifv6Addr {
    /// The IP address of the interface.
    pub ip: Ipv6Addr,
    /// The netmask of the interface.
    pub netmask: Ipv6Addr,
    /// The broadcast address of the interface.
    pub broadcast: Option<Ipv6Addr>,
}

impl Interface {
    /// Check whether this is a loopback interface.
    #[cfg(test)]
    pub fn is_loopback(&self) -> bool {
        self.addr.is_loopback()
    }
}

impl IfAddr {
    /// Check whether this is a loopback address.
    #[cfg(test)]
    pub fn is_loopback(&self) -> bool {
        match *self {
            IfAddr::V4(ref ifv4_addr) => ifv4_addr.is_loopback(),
            IfAddr::V6(ref ifv6_addr) => ifv6_addr.is_loopback(),
        }
    }

    /// Get the IP address of this interface address.
    #[cfg(test)]
    pub fn ip(&self) -> IpAddr {
        match *self {
            IfAddr::V4(ref ifv4_addr) => IpAddr::V4(ifv4_addr.ip),
            IfAddr::V6(ref ifv6_addr) => IpAddr::V6(ifv6_addr.ip),
        }
    }
}

impl Ifv4Addr {
    /// Check whether this is a loopback address.
    #[cfg(test)]
    pub fn is_loopback(&self) -> bool {
        self.ip.octets()[0] == 127
    }
}

impl Ifv6Addr {
    /// Check whether this is a loopback address.
    #[cfg(test)]
    pub fn is_loopback(&self) -> bool {
        self.ip.segments() == [0, 0, 0, 0, 0, 0, 0, 1]
    }
}

#[cfg(not(windows))]
mod getifaddrs_posix {

    use c_linked_list::CLinkedListMut;
    use common::get_if_addrs::{IfAddr, Ifv4Addr, Ifv6Addr, Interface};
    use libc::{AF_INET, AF_INET6};
    use libc::freeifaddrs as posix_freeifaddrs;
    use libc::getifaddrs as posix_getifaddrs;
    use libc::ifaddrs as posix_ifaddrs;
    use libc::sockaddr as posix_sockaddr;
    use libc::sockaddr_in as posix_sockaddr_in;
    use libc::sockaddr_in6 as posix_sockaddr_in6;
    use std::{io, mem};
    use std::ffi::CStr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[allow(unsafe_code)]
    fn sockaddr_to_ipaddr(sockaddr: *const posix_sockaddr) -> Option<IpAddr> {
        if sockaddr.is_null() {
            return None;
        }
        if unsafe { *sockaddr }.sa_family as u32 == AF_INET as u32 {
            let sa = &unsafe { *(sockaddr as *const posix_sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::new(((sa.sin_addr.s_addr) & 255) as u8,
                                          ((sa.sin_addr.s_addr >> 8) & 255) as u8,
                                          ((sa.sin_addr.s_addr >> 16) & 255) as u8,
                                          ((sa.sin_addr.s_addr >> 24) & 255) as u8)))
        } else if unsafe { *sockaddr }.sa_family as u32 == AF_INET6 as u32 {
            let sa = &unsafe { *(sockaddr as *const posix_sockaddr_in6) };
            // Ignore all fe80:: addresses as these are link locals
            if sa.sin6_addr.s6_addr[0] == 0xfe && sa.sin6_addr.s6_addr[1] == 0x80 {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::new(((sa.sin6_addr.s6_addr[0] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[1] as u16,
                                          ((sa.sin6_addr.s6_addr[2] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[3] as u16,
                                          ((sa.sin6_addr.s6_addr[4] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[5] as u16,
                                          ((sa.sin6_addr.s6_addr[6] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[7] as u16,
                                          ((sa.sin6_addr.s6_addr[8] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[9] as u16,
                                          ((sa.sin6_addr.s6_addr[10] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[11] as u16,
                                          ((sa.sin6_addr.s6_addr[12] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[13] as u16,
                                          ((sa.sin6_addr.s6_addr[14] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[15] as u16)))
        } else {
            None
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "nacl"))]
    fn do_broadcast(ifaddr: &posix_ifaddrs) -> Option<IpAddr> {
        sockaddr_to_ipaddr(ifaddr.ifa_ifu)
    }

    #[cfg(any(target_os = "freebsd",
              target_os = "ios",
              target_os = "macos",
              target_os = "openbsd"))]
    fn do_broadcast(ifaddr: &posix_ifaddrs) -> Option<IpAddr> {
        sockaddr_to_ipaddr(ifaddr.ifa_dstaddr)
    }

    /// Return a vector of IP details for all the valid interfaces on this host
    #[allow(unsafe_code)]
    #[allow(trivial_casts)]
    pub fn get_if_addrs() -> io::Result<Vec<Interface>> {
        let mut ret = Vec::<Interface>::new();
        let mut ifaddrs: *mut posix_ifaddrs;
        unsafe {
            ifaddrs = mem::uninitialized();
            if -1 == posix_getifaddrs(&mut ifaddrs) {
                return Err(io::Error::last_os_error());
            }
        }

        for ifaddr in unsafe { CLinkedListMut::from_ptr(ifaddrs, |a| a.ifa_next) }.iter() {
            if ifaddr.ifa_addr.is_null() {
                continue;
            }
            let name = unsafe { CStr::from_ptr(ifaddr.ifa_name as *const _) }
                .to_string_lossy()
                .into_owned();
            let addr = match sockaddr_to_ipaddr(ifaddr.ifa_addr) {
                None => continue,
                Some(IpAddr::V4(ipv4_addr)) => {
                    let netmask = match sockaddr_to_ipaddr(ifaddr.ifa_netmask) {
                        Some(IpAddr::V4(netmask)) => netmask,
                        _ => Ipv4Addr::new(0, 0, 0, 0),
                    };
                    let broadcast = if (ifaddr.ifa_flags & 2) != 0 {
                        match do_broadcast(ifaddr) {
                            Some(IpAddr::V4(broadcast)) => Some(broadcast),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    IfAddr::V4(Ifv4Addr {
                                   ip: ipv4_addr,
                                   netmask: netmask,
                                   broadcast: broadcast,
                               })
                }
                Some(IpAddr::V6(ipv6_addr)) => {
                    let netmask = match sockaddr_to_ipaddr(ifaddr.ifa_netmask) {
                        Some(IpAddr::V6(netmask)) => netmask,
                        _ => Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
                    };
                    let broadcast = if (ifaddr.ifa_flags & 2) != 0 {
                        match do_broadcast(ifaddr) {
                            Some(IpAddr::V6(broadcast)) => Some(broadcast),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    IfAddr::V6(Ifv6Addr {
                                   ip: ipv6_addr,
                                   netmask: netmask,
                                   broadcast: broadcast,
                               })
                }
            };
            ret.push(Interface {
                         name: name,
                         addr: addr,
                     });
        }
        unsafe {
            posix_freeifaddrs(ifaddrs);
        }
        Ok(ret)
    }
}

/// Get a list of all the network interfaces on this machine along with their IP info.
#[cfg(not(windows))]
pub fn get_if_addrs() -> io::Result<Vec<Interface>> {
    getifaddrs_posix::get_if_addrs()
}

#[cfg(windows)]
mod getifaddrs_windows {

    use c_linked_list::CLinkedListConst;
    use common::get_if_addrs::{IfAddr, Ifv4Addr, Ifv6Addr, Interface};
    use libc;
    use libc::{c_char, c_int, c_ulong, c_void, size_t};
    use std::{io, ptr};
    use std::ffi::CStr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use winapi::{AF_INET, AF_INET6, DWORD, ERROR_SUCCESS, sockaddr_in6};
    use winapi::SOCKADDR as sockaddr;
    use winapi::SOCKADDR_IN as sockaddr_in;

    #[repr(C)]
    struct SocketAddress {
        pub lp_socket_address: *const sockaddr,
        pub i_socket_address_length: c_int,
    }
    #[repr(C)]
    struct IpAdapterUnicastAddress {
        pub length: c_ulong,
        pub flags: DWORD,
        pub next: *const IpAdapterUnicastAddress,
        // Loads more follows, but I'm not bothering to map these for now
        pub address: SocketAddress,
    }
    #[repr(C)]
    struct IpAdapterPrefix {
        pub length: c_ulong,
        pub flags: DWORD,
        pub next: *const IpAdapterPrefix,
        pub address: SocketAddress,
        pub prefix_length: c_ulong,
    }
    #[repr(C)]
    struct IpAdapterAddresses {
        pub length: c_ulong,
        pub if_index: DWORD,
        pub next: *const IpAdapterAddresses,
        pub adapter_name: *const c_char,
        pub first_unicast_address: *const IpAdapterUnicastAddress,
        first_anycast_address: *const c_void,
        first_multicast_address: *const c_void,
        first_dns_server_address: *const c_void,
        dns_suffix: *const c_void,
        description: *const c_void,
        friendly_name: *const c_void,
        physical_address: [c_char; 8],
        physical_address_length: DWORD,
        flags: DWORD,
        mtu: DWORD,
        if_type: DWORD,
        oper_status: c_int,
        ipv6_if_index: DWORD,
        zone_indices: [DWORD; 16],
        // Loads more follows, but I'm not bothering to map these for now
        pub first_prefix: *const IpAdapterPrefix,
    }
    #[link(name="Iphlpapi")]
    extern "system" {
        /// get adapter's addresses
        fn GetAdaptersAddresses(family: c_ulong,
                                flags: c_ulong,
                                reserved: *const c_void,
                                addresses: *const IpAdapterAddresses,
                                size: *mut c_ulong)
                                -> c_ulong;
    }

    #[allow(unsafe_code)]
    fn sockaddr_to_ipaddr(sockaddr: *const sockaddr) -> Option<IpAddr> {
        if sockaddr.is_null() {
            return None;
        }
        if unsafe { *sockaddr }.sa_family as u32 == AF_INET as u32 {
            let sa = &unsafe { *(sockaddr as *const sockaddr_in) };
            // Ignore all 169.254.x.x addresses as these are not active interfaces
            if sa.sin_addr.S_un & 65535 == 0xfea9 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(((sa.sin_addr.S_un) & 255) as u8,
                                          ((sa.sin_addr.S_un >> 8) & 255) as u8,
                                          ((sa.sin_addr.S_un >> 16) & 255) as u8,
                                          ((sa.sin_addr.S_un >> 24) & 255) as u8)))
        } else if unsafe { *sockaddr }.sa_family as u32 == AF_INET6 as u32 {
            let sa = &unsafe { *(sockaddr as *const sockaddr_in6) };
            // Ignore all fe80:: addresses as these are link locals
            if sa.sin6_addr.s6_addr[0] == 0xfe && sa.sin6_addr.s6_addr[1] == 0x80 {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::new(((sa.sin6_addr.s6_addr[0] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[1] as u16,
                                          ((sa.sin6_addr.s6_addr[2] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[3] as u16,
                                          ((sa.sin6_addr.s6_addr[4] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[5] as u16,
                                          ((sa.sin6_addr.s6_addr[6] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[7] as u16,
                                          ((sa.sin6_addr.s6_addr[8] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[9] as u16,
                                          ((sa.sin6_addr.s6_addr[10] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[11] as u16,
                                          ((sa.sin6_addr.s6_addr[12] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[13] as u16,
                                          ((sa.sin6_addr.s6_addr[14] as u16 & 255) << 8) |
                                          sa.sin6_addr.s6_addr[15] as u16)))
        } else {
            None
        }
    }

    // trivial_numeric_casts lint may become allow by default.
    // Refer: https://github.com/rust-lang/rfcs/issues/1020
    /// Return a vector of IP details for all the valid interfaces on this host
    #[allow(unsafe_code, trivial_numeric_casts)]
    pub fn get_if_addrs() -> io::Result<Vec<Interface>> {
        let mut ret = Vec::<Interface>::new();
        let mut ifaddrs: *const IpAdapterAddresses;
        let mut buffersize: c_ulong = 15000;
        loop {
            unsafe {
                ifaddrs = libc::malloc(buffersize as size_t) as *mut IpAdapterAddresses;
                if ifaddrs.is_null() {
                    panic!("Failed to allocate buffer in get_if_addrs()");
                }
                let retcode = GetAdaptersAddresses(0,
                                                   // GAA_FLAG_SKIP_ANYCAST       |
                                                   // GAA_FLAG_SKIP_MULTICAST     |
                                                   // GAA_FLAG_SKIP_DNS_SERVER    |
                                                   // GAA_FLAG_INCLUDE_PREFIX     |
                                                   // GAA_FLAG_SKIP_FRIENDLY_NAME
                                                   0x3e,
                                                   ptr::null(),
                                                   ifaddrs,
                                                   &mut buffersize);
                match retcode {
                    ERROR_SUCCESS => break,
                    111 => {
                        libc::free(ifaddrs as *mut c_void);
                        buffersize *= 2;
                        continue;
                    }
                    _ => return Err(io::Error::last_os_error()),
                }
            }
        }

        for ifaddr in unsafe { CLinkedListConst::from_ptr(ifaddrs, |a| a.next) }.iter() {
            for addr in unsafe {
                        CLinkedListConst::from_ptr(ifaddr.first_unicast_address, |a| a.next)
                    }
                    .iter() {
                let name = unsafe { CStr::from_ptr(ifaddr.adapter_name) }
                    .to_string_lossy()
                    .into_owned();

                let addr = match sockaddr_to_ipaddr(addr.address.lp_socket_address) {
                    None => continue,
                    Some(IpAddr::V4(ipv4_addr)) => {
                        let mut item_netmask = Ipv4Addr::new(0, 0, 0, 0);
                        let mut item_broadcast = None;
                        // Search prefixes for a prefix matching addr
                        'prefixloopv4: for prefix in
                            unsafe { CLinkedListConst::from_ptr(ifaddr.first_prefix, |p| p.next) }
                                .iter() {
                            let ipprefix = sockaddr_to_ipaddr(prefix.address.lp_socket_address);
                            match ipprefix {
                                Some(IpAddr::V4(ref a)) => {
                                    let mut netmask: [u8; 4] = [0; 4];
                                    for (n, netmask_elt) in
                                        netmask
                                            .iter_mut()
                                            .enumerate()
                                            .take((prefix.prefix_length as usize + 7) / 8) {
                                        let x_byte = ipv4_addr.octets()[n];
                                        let y_byte = a.octets()[n];
                                        // Clippy 0.0.128 doesn't handle the label on the `continue`
                                        #[cfg_attr(feature="cargo-clippy",
                                                   allow(needless_continue))]
                                        for m in 0..8 {
                                            if (n * 8) + m > prefix.prefix_length as usize {
                                                break;
                                            }
                                            let bit = 1 << m;
                                            if (x_byte & bit) == (y_byte & bit) {
                                                *netmask_elt |= bit;
                                            } else {
                                                continue 'prefixloopv4;
                                            }
                                        }
                                    }
                                    item_netmask = Ipv4Addr::new(netmask[0],
                                                                 netmask[1],
                                                                 netmask[2],
                                                                 netmask[3]);
                                    let mut broadcast: [u8; 4] = ipv4_addr.octets();
                                    for n in 0..4 {
                                        broadcast[n] |= !netmask[n];
                                    }
                                    item_broadcast = Some(Ipv4Addr::new(broadcast[0],
                                                                        broadcast[1],
                                                                        broadcast[2],
                                                                        broadcast[3]));
                                    break 'prefixloopv4;
                                }
                                _ => continue,
                            };
                        }
                        IfAddr::V4(Ifv4Addr {
                                       ip: ipv4_addr,
                                       netmask: item_netmask,
                                       broadcast: item_broadcast,
                                   })
                    }
                    Some(IpAddr::V6(ipv6_addr)) => {
                        let mut item_netmask = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
                        // Search prefixes for a prefix matching addr
                        'prefixloopv6: for prefix in
                            unsafe { CLinkedListConst::from_ptr(ifaddr.first_prefix, |p| p.next) }
                                .iter() {
                            let ipprefix = sockaddr_to_ipaddr(prefix.address.lp_socket_address);
                            match ipprefix {
                                Some(IpAddr::V6(ref a)) => {
                                    // Iterate the bits in the prefix, if they all match this prefix
                                    // is the right one, else try the next prefix
                                    let mut netmask: [u16; 8] = [0; 8];
                                    for (n, netmask_elt) in
                                        netmask
                                            .iter_mut()
                                            .enumerate()
                                            .take((prefix.prefix_length as usize + 15) / 16) {
                                        let x_word = ipv6_addr.segments()[n];
                                        let y_word = a.segments()[n];
                                        // Clippy 0.0.128 doesn't handle the label on the `continue`
                                        #[cfg_attr(feature="cargo-clippy",
                                                   allow(needless_continue))]
                                        for m in 0..16 {
                                            if (n * 16) + m > prefix.prefix_length as usize {
                                                break;
                                            }
                                            let bit = 1 << m;
                                            if (x_word & bit) == (y_word & bit) {
                                                *netmask_elt |= bit;
                                            } else {
                                                continue 'prefixloopv6;
                                            }
                                        }
                                    }
                                    item_netmask = Ipv6Addr::new(netmask[0],
                                                                 netmask[1],
                                                                 netmask[2],
                                                                 netmask[3],
                                                                 netmask[4],
                                                                 netmask[5],
                                                                 netmask[6],
                                                                 netmask[7]);
                                    break 'prefixloopv6;
                                }
                                _ => continue,
                            };
                        }
                        IfAddr::V6(Ifv6Addr {
                                       ip: ipv6_addr,
                                       netmask: item_netmask,
                                       broadcast: None,
                                   })
                    }
                };
                ret.push(Interface {
                             name: name,
                             addr: addr,
                         });
            }
        }
        unsafe {
            libc::free(ifaddrs as *mut c_void);
        }
        Ok(ret)
    }
}

#[cfg(windows)]
/// Get address
pub fn get_if_addrs() -> io::Result<Vec<Interface>> {
    getifaddrs_windows::get_if_addrs()
}

#[cfg(test)]
mod tests {
    use super::Interface;
    use common::get_if_addrs::get_if_addrs;
    use std::error::Error;
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr};
    use std::process::{Command, Stdio};
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;

    fn list_system_interfaces(cmd: &str, arg: &str) -> String {
        let start_cmd = if arg == "" {
            Command::new(cmd).stdout(Stdio::piped()).spawn()
        } else {
            Command::new(cmd)
                .arg(arg)
                .stdout(Stdio::piped())
                .spawn()
        };
        let mut process = match start_cmd {
            Err(why) => {
                println!("couldn't start cmd {} : {}", cmd, why.description());
                return "".to_string();
            }
            Ok(process) => process,
        };
        thread::sleep(Duration::from_millis(1000));
        let _ = process.kill();
        let result: Vec<u8> = unwrap!(process.stdout)
            .bytes()
            .map(|x| unwrap!(x))
            .collect();
        unwrap!(String::from_utf8(result))
    }

    #[cfg(windows)]
    fn list_system_addrs() -> Vec<IpAddr> {
        use std::net::Ipv6Addr;
        list_system_interfaces("ipconfig", "")
            .lines()
            .filter_map(|line| {
                println!("{}", line);
                if line.contains("Address") && !line.contains("Link-local") {
                    let addr_s: Vec<&str> = line.split(" : ").collect();
                    if line.contains("IPv6") {
                        return Some(IpAddr::V6(unwrap!(Ipv6Addr::from_str(addr_s[1]))));
                    } else if line.contains("IPv4") {
                        return Some(IpAddr::V4(unwrap!(Ipv4Addr::from_str(addr_s[1]))));
                    }
                }
                None
            })
            .collect()
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "nacl"))]
    fn list_system_addrs() -> Vec<IpAddr> {
        list_system_interfaces("ip", "addr")
            .lines()
            .filter_map(|line| {
                println!("{}", line);
                if line.contains("inet ") {
                    let addr_s: Vec<&str> = line.split_whitespace().collect();
                    let addr: Vec<&str> = addr_s[1].split('/').collect();
                    return Some(IpAddr::V4(unwrap!(Ipv4Addr::from_str(addr[0]))));
                }
                None
            })
            .collect()
    }

    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
    fn list_system_addrs() -> Vec<IpAddr> {
        list_system_interfaces("ifconfig", "")
            .lines()
            .filter_map(|line| {
                            println!("{}", line);
                            if line.contains("inet ") {
                                let addr_s: Vec<&str> = line.split_whitespace().collect();
                                return Some(IpAddr::V4(unwrap!(Ipv4Addr::from_str(addr_s[1]))));
                            }
                            None
                        })
            .collect()
    }

    #[test]
    fn test_get_if_addrs() {
        let ifaces = unwrap!(get_if_addrs());
        println!("Local interfaces:");
        println!("{:#?}", ifaces);
        // at least one loop back address
        assert!(1 <=
                ifaces
                    .iter()
                    .filter(|interface| interface.is_loopback())
                    .count());
        // one address of IpV4(127.0.0.1)
        let is_loopback =
            |interface: &&Interface| interface.addr.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(1, ifaces.iter().filter(is_loopback).count());

        // each system address shall be listed
        let system_addrs = list_system_addrs();
        assert!(system_addrs.len() >= 1);
        for addr in system_addrs {
            let mut listed = false;
            println!("\n checking whether {:?} has been properly listed \n", addr);
            for interface in &ifaces {
                if interface.addr.ip() == addr {
                    listed = true;
                }
            }
            assert!(listed);
        }
    }
}
