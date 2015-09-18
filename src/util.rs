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

use std::net::SocketAddr;
use std::cmp::Ordering;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
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

pub fn compare_ip_addrs(a1: &SocketAddr, a2: &SocketAddr) -> Ordering {
    use std::net::SocketAddr::{V4,V6};
    match *a1 {
        V4(ref a1) => match *a2 {
            V4(ref a2) => (a1.ip(), a1.port()).cmp(&(a2.ip(), a2.port())),
            V6(_) => Ordering::Less,
        },
        V6(ref a1) => match *a2 {
            V4(_) => Ordering::Greater,
            V6(ref a2) => (a1.ip(), a1.port(), a1.flowinfo(), a1.scope_id())
                          .cmp(&(a2.ip(), a2.port(), a2.flowinfo(), a2.scope_id())),
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
