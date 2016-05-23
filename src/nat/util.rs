use std::io;
use std::net;
use std::net::IpAddr;

use net2;

quick_error! {
    /// Errors returned by new_reusably_bound_tcp_socket
    #[derive(Debug)]
    pub enum NewReusablyBoundTcpSocketError {
        /// Error creating socket.
        Create { err: io::Error } {
            description("Error creating socket.")
            display("Error creating socket: {}", err)
            cause(err)
        }
        /// Error setting SO_REUSEADDR on socket.
        EnableReuseAddr { err: io::Error } {
            description("Error setting SO_REUSEADDR on socket.")
            display("Error setting SO_REUSEADDR on socket. \
                     Got IO error: {}", err)
            cause(err)
        }
        /// Error setting SO_REUSEPORT (or equivalent) on socket.
        EnableReusePort { err: io::Error } {
            description("Error setting SO_REUSEPORT (or equivalent) on socket.")
            display("Error setting SO_REUSEPORT (or equivalent) on socket. \
                     Got IO error: {}", err)
            cause(err)
        }
        /// Error binding new socket to the provided address. Likely a socket was already bound to
        /// this address without SO_REUSEPORT and SO_REUSEADDR being set.
        Bind { err: io::Error } {
            description("Error binding new socket to the provided address. Likely a socket was \
                         already bound to this address without SO_REUSEPORT and SO_REUSEADDR \
                         being set")
            display("Error binding new socket to the provided address: {}. Likely a socket was \
                     already bound to this address without SO_REUSEPORT and SO_REUSEADDR being \
                     set", err)
            cause(err)
        }
    }
}

impl From<NewReusablyBoundTcpSocketError> for io::Error {
    fn from(e: NewReusablyBoundTcpSocketError) -> io::Error {
        let err_str = format!("{}", e);
        let kind = match e {
            NewReusablyBoundTcpSocketError::Create { err } => err.kind(),
            NewReusablyBoundTcpSocketError::EnableReuseAddr { err } => err.kind(),
            NewReusablyBoundTcpSocketError::EnableReusePort { err } => err.kind(),
            NewReusablyBoundTcpSocketError::Bind { err } => err.kind(),
        };
        io::Error::new(kind, err_str)
    }
}

pub fn new_reusably_bound_tcp_socket(local_addr: &net::SocketAddr) -> Result<net2::TcpBuilder, NewReusablyBoundTcpSocketError> {
    let socket_res = match local_addr.ip() {
        IpAddr::V4(..) => net2::TcpBuilder::new_v4(),
        IpAddr::V6(..) => net2::TcpBuilder::new_v6(),
    };
    let socket = match socket_res {
        Ok(socket) => socket,
        Err(e) => return Err(NewReusablyBoundTcpSocketError::Create { err: e }),
    };
    match socket.reuse_address(true) {
        Ok(_) => (),
        Err(e) => return Err(NewReusablyBoundTcpSocketError::EnableReuseAddr { err: e }),
    };
    match enable_so_reuseport(&socket) {
        Ok(()) => (),
        Err(e) => return Err(NewReusablyBoundTcpSocketError::EnableReusePort { err: e }),
    };
    match socket.bind(local_addr) {
        Ok(..) => (),
        Err(e) => return Err(NewReusablyBoundTcpSocketError::Bind { err: e }),
    };
    Ok(socket)
}

#[cfg(target_family = "unix")]
pub fn enable_so_reuseport(sock: &net2::TcpBuilder) -> io::Result<()> {
    use net2::unix::UnixTcpBuilderExt;
    let _ = try!(sock.reuse_port(true));
    Ok(())
}

#[cfg(target_family = "windows")]
pub fn enable_so_reuseport(_sock: &net2::TcpBuilder) -> io::Result<()> {
    Ok(())
}

// TODO(canndrew): This function should be deprecated once this issue
// (https://github.com/rust-lang-nursery/net2-rs/issues/26) is resolved.
#[cfg(target_family = "unix")]
#[allow(unsafe_code)]
pub fn tcp_builder_local_addr(sock: &net2::TcpBuilder) -> io::Result<net::SocketAddr> {
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
    let fd = sock.as_raw_fd();
    let stream = unsafe { net::TcpStream::from_raw_fd(fd) };
    let ret = stream.local_addr();
    let _ = stream.into_raw_fd();
    ret
}

#[cfg(target_family = "windows")]
#[allow(unsafe_code)]
pub fn tcp_builder_local_addr(sock: &net2::TcpBuilder) -> io::Result<net::SocketAddr> {
    use std::mem;
    use std::os::windows::io::{AsRawSocket, FromRawSocket};
    let fd = sock.as_raw_socket();
    let stream = unsafe { net::TcpStream::from_raw_socket(fd) };
    let ret = stream.local_addr();
    mem::forget(stream); // TODO(canndrew): Is this completely safe?
    ret
}

