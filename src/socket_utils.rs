use std::io;
use std::net::{UdpSocket, SocketAddr};
use std::io::ErrorKind;

/// A self interruptable receive trait that allows a timed-out period to be defined
pub trait RecvUntil {
    /// After specified timed-out period, the blocking receive method shall return with an error
    fn recv_until(&self,
                  buf: &mut [u8],
                  deadline: ::time::SteadyTime)
                  -> io::Result<Option<(usize, SocketAddr)>>;
}

impl RecvUntil for UdpSocket {
    fn recv_until(&self,
                  buf: &mut [u8],
                  deadline: ::time::SteadyTime)
                  -> io::Result<Option<(usize, SocketAddr)>> {
        loop {
            let current_time = ::time::SteadyTime::now();
            let timeout_ms = (deadline - current_time).num_milliseconds();

            if timeout_ms <= 0 {
                return Ok(None);
            }

            // TODO (canndrew): should eventually be able to remove this conversion
            let timeout = ::std::time::Duration::from_millis(timeout_ms as u64);
            try!(self.set_read_timeout(Some(timeout)));

            match self.recv_from(buf) {
                Ok(x) => return Ok(Some(x)),
                Err(e) => {
                    match e.kind() {
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
                        _ => return Err(e),
                    }
                }
            }
        }
    }
}
