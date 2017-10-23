use util;
use priv_prelude::*;

/// Punch a hole to a remote peer. Both peers call this simultaneously try to perform a TCP
/// rendezvous connect to each other.
pub fn tcp_hole_punch(
    handle: &Handle,
    socket: TcpBuilder,
    remote_addrs: &[SocketAddr],
) -> io::Result<IoStream<(TcpStream, SocketAddr)>> {
    let mut sockets = Vec::new();
    let local_addr = socket.local_addr()?;
    for addr in remote_addrs {
        let socket = util::new_reusably_bound_tcp_socket(&local_addr)?;
        let socket = socket.to_tcp_stream()?;
        sockets.push((socket, *addr));
    };
    let listener = socket.listen(100)?;
    let listener = TcpListener::from_listener(listener, &local_addr, handle)?;
    let incoming = listener.incoming();

    let connectors = {
        sockets
        .into_iter()
        .map(|(socket, addr)| {
            TcpStream::connect_stream(socket, &addr, handle)
            .map(move |stream| (stream, addr))
        })
        .collect::<Vec<_>>()
    };
    let outgoing = stream::futures_unordered(connectors);
    Ok(outgoing.select(incoming).into_boxed())
}

