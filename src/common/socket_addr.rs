use std::net;
use std::ops::Deref;
use std::str::FromStr;
use std::fmt;
use rustc_serialize::{Encodable, Decodable, Encoder, Decoder};

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
        let as_string = try!(d.read_str());
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
        let as_string = try!(d.read_str());
        match net::SocketAddrV4::from_str(&as_string[..]) {
            Ok(sa) => Ok(SocketAddrV4(sa)),
            Err(e) => {
                let err = format!("Failed to decode SocketAddrV4: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}

/// Utility struct of SocketAddrV6 for hole punching
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
        let as_string = try!(d.read_str());
        match net::SocketAddrV6::from_str(&as_string[..]) {
            Ok(sa) => Ok(SocketAddrV6(sa)),
            Err(e) => {
                let err = format!("Failed to decode SocketAddrV6: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}

