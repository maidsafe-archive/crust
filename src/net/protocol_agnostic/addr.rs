// Copyright 2017 MaidSafe.net limited.
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

use priv_prelude::*;
use serde;
use std::fmt;
use std::net;
use std::str::FromStr;
use url::{self, Url};

/// Protocol agnostic address.
/// Let's you match the address by it's protocol.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum PaAddr {
    /// TCP socket address.
    Tcp(SocketAddr),
    /// uTP socket address.
    Utp(SocketAddr),
}

impl PaAddr {
    /// Returns socket IP address.
    pub fn ip(&self) -> IpAddr {
        match *self {
            PaAddr::Tcp(ref addr) |
            PaAddr::Utp(ref addr) => addr.ip(),
        }
    }

    /// Returns all local addresses, if socket address is unspecified - '0.0.0.0'.
    /// Otherwise a list with only current address is returned.
    pub fn expand_local_unspecified(&self) -> io::Result<Vec<PaAddr>> {
        match *self {
            PaAddr::Tcp(ref addr) => {
                Ok(
                    addr.expand_local_unspecified()?
                        .into_iter()
                        .map(PaAddr::Tcp)
                        .collect(),
                )
            }
            PaAddr::Utp(ref addr) => {
                Ok(
                    addr.expand_local_unspecified()?
                        .into_iter()
                        .map(PaAddr::Utp)
                        .collect(),
                )
            }
        }
    }

    #[cfg(test)]
    pub fn unspecified_to_localhost(&self) -> PaAddr {
        match *self {
            PaAddr::Tcp(ref addr) => {
                if addr.ip().is_unspecified() {
                    PaAddr::Tcp(SocketAddr::new(ip!("127.0.0.1"), addr.port()))
                } else {
                    PaAddr::Tcp(*addr)
                }
            }
            PaAddr::Utp(ref addr) => {
                if addr.ip().is_unspecified() {
                    PaAddr::Utp(SocketAddr::new(ip!("127.0.0.1"), addr.port()))
                } else {
                    PaAddr::Utp(*addr)
                }
            }
        }
    }

    /// Checks if this is TCP address.
    pub fn is_tcp(&self) -> bool {
        match *self {
            PaAddr::Tcp(..) => true,
            _ => false,
        }
    }

    /// Checks if this is UDP address.
    pub fn is_utp(&self) -> bool {
        match *self {
            PaAddr::Utp(..) => true,
            _ => false,
        }
    }
}

impl fmt::Display for PaAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PaAddr::Tcp(ref addr) => write!(f, "tcp://{}", addr),
            PaAddr::Utp(ref addr) => write!(f, "utp://{}", addr),
        }
    }
}

impl Serialize for PaAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = format!("{}", self);
        s.serialize(serializer)
    }
}

struct PaAddrVisitor;

impl<'de> serde::de::Visitor<'de> for PaAddrVisitor {
    type Value = PaAddr;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a url string representing a protocol and address")
    }

    fn visit_str<E>(self, v: &str) -> Result<PaAddr, E>
    where
        E: serde::de::Error,
    {
        match v.parse() {
            Ok(addr) => Ok(addr),
            Err(e) => Err(E::custom(e)),
        }
    }
}

impl<'de> serde::Deserialize<'de> for PaAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(PaAddrVisitor)
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ParseError {
        MalformedUrl(e: url::ParseError) {
            description("malformed url")
            display("malformed url. {}", e)
            cause(e)
        }
        MalformedHost(e: net::AddrParseError) {
            description("malformed host")
            display("malformed host. {}", e)
            cause(e)
        }
        UnknownScheme(s: String) {
            description("unknown scheme")
            display("unknown scheme: \"{}\"", s)
        }
        MissingPort {
            description("missing port number")
        }
    }
}

impl FromStr for PaAddr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<PaAddr, ParseError> {
        let url = match Url::parse(s) {
            Ok(url) => url,
            Err(e) => return Err(ParseError::MalformedUrl(e)),
        };
        let ret = match url.scheme() {
            "tcp" => PaAddr::Tcp(addr_from_url(&url)?),
            "utp" => PaAddr::Utp(addr_from_url(&url)?),
            scheme => return Err(ParseError::UnknownScheme(scheme.to_owned())),
        };
        Ok(ret)
    }
}

fn addr_from_url(url: &Url) -> Result<SocketAddr, ParseError> {
    let ip = match url.host_str() {
        None => return Err(ParseError::MalformedUrl(url::ParseError::EmptyHost)),
        Some(host) => {
            match IpAddr::from_str(host) {
                Err(e) => return Err(ParseError::MalformedHost(e)),
                Ok(addr) => addr,
            }
        }
    };
    let port = match url.port() {
        Some(port) => port,
        None => return Err(ParseError::MissingPort),
    };
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod test {
    use priv_prelude::*;
    use std::str::FromStr;

    #[test]
    fn test_url_parsing_and_formatting_are_inverse() {
        let strings = &["tcp://127.0.0.1:45666", "utp://127.0.0.1:45666"];
        for str_in in strings {
            let addr = unwrap!(PaAddr::from_str(str_in));
            let str_out = format!("{}", addr);
            assert_eq!(*str_in, str_out);
        }
    }
}
