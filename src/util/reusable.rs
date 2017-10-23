use priv_prelude::*;

pub fn new_reusably_bound_tcp_socket(local_addr: &SocketAddr) -> io::Result<TcpBuilder> {
    let socket = match local_addr.ip() {
        IpAddr::V4(..) => TcpBuilder::new_v4()?,
        IpAddr::V6(..) => TcpBuilder::new_v6()?,
    };
    let _ = socket.reuse_address(true)?;
    enable_so_reuseport(&socket)?;
    let _ = socket.bind(local_addr)?;

    Ok(socket)
}

#[cfg(target_family = "unix")]
pub fn enable_so_reuseport(sock: &TcpBuilder) -> io::Result<()> {
    use net2::unix::UnixTcpBuilderExt;
    let _ = sock.reuse_port(true)?;
    Ok(())
}

#[cfg(target_family = "windows")]
pub fn enable_so_reuseport(_sock: &TcpBuilder) -> io::Result<()> {
    Ok(())
}

