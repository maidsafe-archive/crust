use std::io;
use std::net;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

use net2;
use get_if_addrs;
use get_if_addrs::IfAddr;

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

pub fn new_reusably_bound_tcp_socket(local_addr: &SocketAddr) -> Result<net2::TcpBuilder, NewReusablyBoundTcpSocketError> {
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
pub fn tcp_builder_local_addr(sock: &net2::TcpBuilder) -> io::Result<SocketAddr> {
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

pub fn expand_unspecified_addr(addr: SocketAddr) -> io::Result<Vec<SocketAddr>> {
    let ip = addr.ip();
    let ips = try!(expand_unspecified_ip(ip));
    let port = addr.port();
    Ok(ips.into_iter().map(|i| SocketAddr::new(i, port)).collect())
}

pub fn expand_unspecified_ip(ip: IpAddr) -> io::Result<Vec<IpAddr>> {
    Ok(match ip {
        IpAddr::V4(ipv4) => try!(expand_unspecified_ipv4(ipv4)).into_iter().map(|ipv4| {
            IpAddr::V4(ipv4)
        }).collect(),
        IpAddr::V6(ipv6) => try!(expand_unspecified_ipv6(ipv6)).into_iter().map(|ipv6| {
            IpAddr::V6(ipv6)
        }).collect(),
    })
}

pub fn expand_unspecified_ipv4(ipv4: Ipv4Addr) -> io::Result<Vec<Ipv4Addr>> {
    Ok(if ipv4_is_unspecified(&ipv4) {
        let mut ret = Vec::new();
        for iface in try!(get_if_addrs::get_if_addrs()) {
            match iface.addr {
                IfAddr::V4(ifv4_addr) => ret.push(ifv4_addr.ip),
                _ => (),
            }
        }
        ret
    }
    else {
        vec![ipv4]
    })
}

pub fn expand_unspecified_ipv6(ipv6: Ipv6Addr) -> io::Result<Vec<Ipv6Addr>> {
    Ok(if ipv6.is_unspecified() {
        let mut ret = Vec::new();
        for iface in try!(get_if_addrs::get_if_addrs()) {
            match iface.addr {
                IfAddr::V6(ifv6_addr) => ret.push(ifv6_addr.ip),
                _ => (),
            }
        }
        ret
    }
    else {
        vec![ipv6]
    })
}

pub fn ipv4_is_unspecified(ip: &Ipv4Addr) -> bool {
    ip.octets() == [0, 0, 0, 0]
}

