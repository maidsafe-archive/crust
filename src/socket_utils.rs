use std::io;
use std::net::{UdpSocket, SocketAddr};
use std::io::ErrorKind;

pub trait RecvUntil {
    fn recv_until(&self, buf: &mut [u8], deadline: ::time::SteadyTime) -> io::Result<Option<(usize, SocketAddr)>>;
}

impl RecvUntil for UdpSocket {
    fn recv_until(&self, buf: &mut [u8], deadline: ::time::SteadyTime) -> io::Result<Option<(usize, SocketAddr)>> {
        loop {
            let current_time = ::time::SteadyTime::now();
            let timeout = deadline - current_time;
            if timeout < ::time::Duration::zero() {
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
                        _   => return Err(e),
                    },
                }
            }
        }
    }
}

