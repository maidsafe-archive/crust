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

/// Simple wrapper for an endpoint.
#[derive(PartialEq, Eq, Hash, Debug, Clone, RustcDecodable, RustcEncodable)]
pub struct Contact {
    pub endpoint: ::transport::Endpoint
}

/// Collection of contacts.
pub type Contacts = Vec<Contact>;

#[cfg(test)]
pub fn random_contact() -> Contact {
    // TODO - randomise V4/V6 and TCP/UTP
    let address = ::std::net::SocketAddrV4::new(
        ::std::net::Ipv4Addr::new(::rand::random::<u8>(),
                                  ::rand::random::<u8>(),
                                  ::rand::random::<u8>(),
                                  ::rand::random::<u8>()),
        ::rand::random::<u16>());
    Contact{ endpoint: ::transport::Endpoint::Tcp(::std::net::SocketAddr::V4(address)) }
}

#[cfg(test)]
pub fn random_contacts(count: usize) -> Contacts {
    let mut contacts = Vec::new();
    for _ in 0..count {
        contacts.push(random_contact());
    }
    contacts
}
