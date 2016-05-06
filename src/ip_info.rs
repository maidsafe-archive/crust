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
}

pub mod v6 {
    use std::net::Ipv6Addr;

    pub fn is_unique_local(a: &Ipv6Addr) -> bool {
        (a.segments()[0] & 0xfe00) == 0xfc00
    }

    pub fn is_unicast_link_local(a: &Ipv6Addr) -> bool {
        (a.segments()[0] & 0xffc0) == 0xfe80
    }
}
