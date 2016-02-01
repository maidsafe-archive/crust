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

use std::io;
use std::net::UdpSocket;
use socket_addr::SocketAddr;
use std::io::ErrorKind;
use net2::TcpBuilder;

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
                Ok((bytes_len, addr)) => return Ok(Some((bytes_len, SocketAddr(addr)))),
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

#[cfg(target_family = "unix")]
#[allow(unsafe_code)]
pub fn enable_so_reuseport(sock: &TcpBuilder) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    use libc;
    use std;

    let one: libc::c_int = 1;
    let raw_fd = sock.as_raw_fd();
    let one_ptr: *const libc::c_int = &one;
    unsafe {
        if libc::setsockopt(raw_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            one_ptr as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t
        ) < 0
        {
            return Err(io::Error::last_os_error());
        };
    }
    Ok(())
}

#[cfg(not(target_family = "unix"))]
pub fn enable_so_reuseport(sock: &TcpBuilder) -> io::Result<()> {
    Ok(())
}

