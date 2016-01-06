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


/// Replacements for std::net functions behind the ip feature gate.
/// TODO: when ip becomes stable, remove this.

pub mod v4 {
    use std::net::Ipv4Addr;

    pub fn is_unspecified(a: &Ipv4Addr) -> bool {
        a.octets() == [0, 0, 0, 0]
    }

    pub fn is_loopback(a: &Ipv4Addr) -> bool {
        a.octets()[0] == 127
    }

    pub fn is_global(a: &Ipv4Addr) -> bool {
        !is_private(a) &&
        !is_loopback(a) &&
        !is_link_local(a) &&
        !is_broadcast(a) &&
        !is_documentation(a)
    }

    pub fn is_broadcast(a: &Ipv4Addr) -> bool {
        a.octets()[0] == 255 && a.octets()[1] == 255 &&
        a.octets()[2] == 255 && a.octets()[3] == 255
    }

    pub fn is_documentation(a: &Ipv4Addr) -> bool {
        match(a.octets()[0], a.octets()[1], a.octets()[2], a.octets()[3]) {
            (192, 0, 2, _) => true,
            (198, 51, 100, _) => true,
            (203, 0, 113, _) => true,
            _ => false
        }
    }

    pub fn is_private(a: &Ipv4Addr) -> bool {
        match (a.octets()[0], a.octets()[1]) {
            (10, _) => true,
            (172, b) if b >= 16 && b <= 31 => true,
            (192, 168) => true,
            _ => false
        }
    }

    pub fn is_link_local(a: &Ipv4Addr) -> bool {
        a.octets()[0] == 169 && a.octets()[1] == 254
    }
}

pub mod v6 {
    use std::net::Ipv6Addr;

    #[derive(Copy, PartialEq, Eq, Clone, Hash, Debug)]
    pub enum Ipv6MulticastScope {
        InterfaceLocal,
        LinkLocal,
        RealmLocal,
        AdminLocal,
        SiteLocal,
        OrganizationLocal,
        Global
    }

    pub fn is_unspecified(a: &Ipv6Addr) -> bool {
        a.segments() == [0, 0, 0, 0, 0, 0, 0, 0]
    }

    pub fn is_loopback(a: &Ipv6Addr) -> bool {
        a.segments() == [0, 0, 0, 0, 0, 0, 0, 1]
    }

    pub fn is_global(a: &Ipv6Addr) -> bool {
        match multicast_scope(a) {
            Some(Ipv6MulticastScope::Global) => true,
            None => is_unicast_global(a),
            _ => false
        }
    }

    pub fn is_unique_local(a: &Ipv6Addr) -> bool {
        (a.segments()[0] & 0xfe00) == 0xfc00
    }

    pub fn is_unicast_link_local(a: &Ipv6Addr) -> bool {
        (a.segments()[0] & 0xffc0) == 0xfe80
    }

    pub fn is_unicast_site_local(a : &Ipv6Addr) -> bool {
        (a.segments()[0] & 0xffc0) == 0xfec0
    }

    pub fn is_unicast_global(a: &Ipv6Addr) -> bool {
        !is_multicast(a) &&
        !is_loopback(a) &&
        !is_unicast_link_local(a) &&
        !is_unicast_site_local(a) &&
        !is_unique_local(a)
    }

    pub fn is_multicast(a: &Ipv6Addr) -> bool {
        (a.segments()[0] & 0xff00) == 0xff00
    }

    pub fn multicast_scope(a: &Ipv6Addr) -> Option<Ipv6MulticastScope> {
        if is_multicast(a) {
            match a.segments()[0] & 0x000f {
                1 => Some(Ipv6MulticastScope::InterfaceLocal),
                2 => Some(Ipv6MulticastScope::LinkLocal),
                3 => Some(Ipv6MulticastScope::RealmLocal),
                4 => Some(Ipv6MulticastScope::AdminLocal),
                5 => Some(Ipv6MulticastScope::SiteLocal),
                8 => Some(Ipv6MulticastScope::OrganizationLocal),
                14 => Some(Ipv6MulticastScope::Global),
                _ => None
            }
        } else {
            None
        }
    }
}
