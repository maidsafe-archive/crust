use std::io;
use std::net::{UdpSocket, SocketAddr, SocketAddrV4};
use std::io::ErrorKind;
use std::str::FromStr;

pub trait RecvUntil {
    fn recv_until(&self, buf: &mut [u8], deadline: ::time::SteadyTime) -> io::Result<Option<(usize, SocketAddr)>>;
}

impl RecvUntil for UdpSocket {
    fn recv_until(&self, buf: &mut [u8], deadline: ::time::SteadyTime) -> io::Result<Option<(usize, SocketAddr)>> {
        loop {
            let current_time = ::time::SteadyTime::now();
            let timeout = deadline - current_time;
            if timeout <= ::time::Duration::zero() {
                return Ok(None);
            }
            else {
                // TODO (canndrew): should eventually be able to remove this conversion
                let timeout = ::std::time::Duration::from_millis(timeout.num_milliseconds() as u64);
                try!(self.set_read_timeout(Some(timeout)));
                match self.recv_from(buf) {
                    Ok(x)   => return Ok(Some(x)),
                    Err(e)  => match e.kind() {
                        ErrorKind::TimedOut | ErrorKind::WouldBlock => return Ok(None),
                        ErrorKind::Interrupted => (),
                        // On Windows, when we send a packet to an endpoint
                        // which is not being listened on, the system responds
                        // with an ICMP packet "ICMP port unreachable".
                        // We do not care about this silly behavior, so we just
                        // ignore it.
                        // See here for more info:
                        // https://bobobobo.wordpress.com/2009/05/17/udp-an-existing-connection-was-forcibly-closed-by-the-remote-host/
                        ErrorKind::ConnectionReset => (),
                        _   => return Err(e),
                    },
                }
            }
        }
    }
}

/// This type exists solely because there is no impl of `Encodable` for `SocketAddr`.
#[derive(Debug, Clone)]
pub struct WrapSocketAddr(pub SocketAddr);

impl ::rustc_serialize::Encodable for WrapSocketAddr {
    fn encode<S: ::rustc_serialize::Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let as_string = format!("{}", self.0);
        try!(s.emit_str(&as_string[..]));
        Ok(())
    }
}

impl ::rustc_serialize::Decodable for WrapSocketAddr {
    fn decode<D: ::rustc_serialize::Decoder>(d: &mut D) -> Result<WrapSocketAddr, D::Error> {
        let as_string = try!(d.read_str());
        match SocketAddr::from_str(&as_string[..]) {
            Ok(sa)  => Ok(WrapSocketAddr(sa)),
            Err(e)  => {
                let err = format!("Failed to decode WrapSocketAddr: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}

/// This type exists solely because there is no impl of `Encodable` for `SocketAddrV4`.
#[derive(Debug, Clone)]
pub struct WrapSocketAddrV4(pub SocketAddrV4);

impl ::rustc_serialize::Encodable for WrapSocketAddrV4 {
    fn encode<S: ::rustc_serialize::Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let as_string = format!("{}", self.0);
        try!(s.emit_str(&as_string[..]));
        Ok(())
    }
}

impl ::rustc_serialize::Decodable for WrapSocketAddrV4 {
    fn decode<D: ::rustc_serialize::Decoder>(d: &mut D) -> Result<WrapSocketAddrV4, D::Error> {
        let as_string = try!(d.read_str());
        match SocketAddr::from_str(&as_string[..]) {
            Ok(SocketAddr::V4(sa))  => Ok(WrapSocketAddrV4(sa)),
            Ok(SocketAddr::V6(sa))  => {
                let err = format!("Decoded an ipv6 address where ipv4 was expected");
                Err(d.error(&err[..]))
            },
            Err(e)  => {
                let err = format!("Failed to decode WrapSocketAddrV4: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}


