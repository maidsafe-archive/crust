
// Copyright 2016 MaidSafe.net limited.
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

use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::fmt;
use std::net;
use std::ops::Deref;
use std::str::FromStr;

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
/// Wrapper around `std::net::SocketAddr` to enable it to be encoded and decoded.
pub struct SocketAddr(pub net::SocketAddr);

impl Deref for SocketAddr {
    type Target = net::SocketAddr;

    fn deref(&self) -> &net::SocketAddr {
        &self.0
    }
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Encodable for SocketAddr {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let as_string = format!("{}", self.0);
        s.emit_str(&as_string[..])
    }
}

impl Decodable for SocketAddr {
    fn decode<D: Decoder>(d: &mut D) -> Result<SocketAddr, D::Error> {
        let as_string = d.read_str()?;
        match net::SocketAddr::from_str(&as_string[..]) {
            Ok(sa) => Ok(SocketAddr(sa)),
            Err(e) => {
                let err = format!("Failed to decode SocketAddr: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}

impl SocketAddr {
    /// Construct new from `IpAddr` and port.
    pub fn new(ip: net::IpAddr, port: u16) -> Self {
        SocketAddr(net::SocketAddr::new(ip, port))
    }
}

/// Utility struct of `SocketAddrV4` for hole punching
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SocketAddrV4(pub net::SocketAddrV4);

impl Deref for SocketAddrV4 {
    type Target = net::SocketAddrV4;

    fn deref(&self) -> &net::SocketAddrV4 {
        &self.0
    }
}

impl Encodable for SocketAddrV4 {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let as_string = format!("{}", self.0);
        s.emit_str(&as_string[..])
    }
}

impl Decodable for SocketAddrV4 {
    fn decode<D: Decoder>(d: &mut D) -> Result<SocketAddrV4, D::Error> {
        let as_string = d.read_str()?;
        match net::SocketAddrV4::from_str(&as_string[..]) {
            Ok(sa) => Ok(SocketAddrV4(sa)),
            Err(e) => {
                let err = format!("Failed to decode SocketAddrV4: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}

/// Wrapper for `SocketAddrV6` which implements `Encodable`/`Decodable`.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SocketAddrV6(pub net::SocketAddrV6);

impl Deref for SocketAddrV6 {
    type Target = net::SocketAddrV6;

    fn deref(&self) -> &net::SocketAddrV6 {
        &self.0
    }
}

impl Encodable for SocketAddrV6 {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let as_string = format!("{}", self.0);
        s.emit_str(&as_string[..])
    }
}

impl Decodable for SocketAddrV6 {
    fn decode<D: Decoder>(d: &mut D) -> Result<SocketAddrV6, D::Error> {
        let as_string = d.read_str()?;
        match net::SocketAddrV6::from_str(&as_string[..]) {
            Ok(sa) => Ok(SocketAddrV6(sa)),
            Err(e) => {
                let err = format!("Failed to decode SocketAddrV6: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
/// Wrapper around `std::net::IpAddr` to enable encoding/decoding of IP addresses without port.
pub struct IpAddr(pub net::IpAddr);

impl Deref for IpAddr {
    type Target = net::IpAddr;

    fn deref(&self) -> &net::IpAddr {
        &self.0
    }
}

impl From<SocketAddr> for IpAddr {
    fn from(sa: SocketAddr) -> IpAddr {
        let s = format!("{}", sa);
        let port = s.find(':').unwrap_or(0);
        let (ip, _) = s.split_at(port);

        if let Ok(ia) = net::IpAddr::from_str(ip) {
            IpAddr(ia)
        } else {
            panic!("Invalid SocketAddr format")
        }
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Encodable for IpAddr {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let as_string = format!("{}", self.0);
        s.emit_str(&as_string[..])
    }
}

impl Decodable for IpAddr {
    fn decode<D: Decoder>(d: &mut D) -> Result<IpAddr, D::Error> {
        let as_string = d.read_str()?;
        match net::IpAddr::from_str(&as_string[..]) {
            Ok(ia) => Ok(IpAddr(ia)),
            Err(e) => {
                let err = format!("Failed to decode IpAddr: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}
