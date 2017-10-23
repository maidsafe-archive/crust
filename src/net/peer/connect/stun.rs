use priv_prelude::*;
use util;
use net::peer::connect::HandshakeMessage;

quick_error! {
    #[derive(Debug)]
    pub enum StunError {
        Connect(e: io::Error) {
            description("error connecting to peer")
            display("error connecting to peer: {}", e)
            cause(e)
        }
        UnexpectedResponse {
            description("the peer replied with an unexpected message")
        }
        Disconnected {
            description("disconnected from the remote peer")
        }
        Socket(e: SocketError) {
            description("error on the socket")
            display("error on the socket: {}", e)
            cause(e)
        }
        TimerIo(e: io::Error) {
            description("io error creating tokio timer")
            display("io error creating tokio timer: {}", e)
            cause(e)
        }
        TimedOut {
            description("operation timed out")
        }
        CreateReusableSocket(e: io::Error) {
            description("error creating reusably-bound tcp socket")
            display("error creating reusably-bound tcp socket: {}", e)
            cause(e)
        }
    }
}

/// Perform a "stun" (not actually stun, but our own stun-like protocol) to determine our remote
/// address.
pub fn stun<UID: Uid>(
    handle: &Handle,
    local_addr: &SocketAddr,
    peer_addr: &SocketAddr,
) -> BoxFuture<SocketAddr, StunError> {
    let handle0 = handle.clone();
    let handle1 = handle.clone();
    let peer_addr = *peer_addr;
    future::result({
        util::new_reusably_bound_tcp_socket(local_addr)
        .and_then(|socket| socket.to_tcp_stream())
        .map_err(StunError::CreateReusableSocket)
    })
    .and_then(move |socket| {
        TcpStream::connect_stream(socket, &peer_addr, &handle0)
        .map_err(StunError::Connect)
    })
    .map(move |stream| Socket::<HandshakeMessage<UID>>::wrap_tcp(&handle1, stream, peer_addr))
    .and_then(|socket| {
        socket
        .send((0, HandshakeMessage::EchoAddrReq))
        .and_then(|socket| {
            socket
            .into_future()
            .map_err(|(e, _)| e)
        })
        .map_err(StunError::Socket)
        .and_then(|(msg_opt, _socket)| {
            match msg_opt {
                Some(HandshakeMessage::EchoAddrResp(addr)) => Ok(addr),
                Some(..) => Err(StunError::UnexpectedResponse),
                None => Err(StunError::Disconnected),
            }
        })
    })
    .with_timeout(handle, Duration::from_secs(3), StunError::TimedOut)
    .into_boxed()
}

pub fn stun_respond<UID: Uid>(
    socket: Socket<HandshakeMessage<UID>>,
) -> BoxFuture<(), SocketError> {
    let addr = match socket.peer_addr() {
        Ok(addr) => addr,
        Err(e) => return future::err(e).into_boxed(),
    };

    socket.send((0, HandshakeMessage::EchoAddrResp(addr)))
    .map(|_s| ())
    .into_boxed()
}

