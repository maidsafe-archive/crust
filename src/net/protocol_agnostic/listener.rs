// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use futures::stream::FuturesUnordered;
use net::protocol_agnostic::CRUST_TCP_INIT;
use p2p::{self, ECHO_REQ, P2p, RendezvousServerError, tcp_respond_with_addr, udp_respond_with_addr};
use priv_prelude::*;
use tokio_core;
use tokio_utp;

#[derive(Debug)]
pub enum PaListener {
    Tcp(TcpListener),
    Utp(UtpSocket, UtpListener),
}

pub struct PaIncoming {
    inner: PaIncomingInner,
}

enum PaIncomingInner {
    Tcp {
        incoming: tokio_core::net::Incoming,
        processing: FuturesUnordered<BoxFuture<Option<(FramedPaStream, SocketAddr)>, AcceptError>>,
    },
    Utp {
        incoming: tokio_utp::Incoming,
        raw_rx: tokio_utp::RawReceiver,
        processing: FuturesUnordered<BoxFuture<(), AcceptError>>,
    },
}

quick_error! {
    #[derive(Debug)]
    pub enum BindPublicError {
        BindTcp(e: p2p::BindPublicError) {
            description("error binding tcp listener publicly")
            display("error binding tcp listener publicly: {}", e)
            cause(e)
        }
        BindUdp(e: p2p::BindPublicError) {
            description("error binding udp socket publicly")
            display("error binding udp socket publicly: {}", e)
            cause(e)
        }
        MakeUtpSocket(e: io::Error) {
            description("error making utp socket from udp socket")
            display("error making utp socket from udp socket: {}", e)
            cause(e)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum AcceptError {
        TcpAccept(e: io::Error) {
            description("error accepting tcp connection")
            display("error accepting tcp connection: {}", e)
            cause(e)
        }
        UtpAccept(e: io::Error) {
            description("error accepting utp connection")
            display("error accepting utp connection: {}", e)
            cause(e)
        }
        InvalidTcpHeader {
            description("invalid header on incoming tcp connection")
        }
        InvalidUdpHeader {
            description("invalid header on incoming udp connection")
        }
        TcpReadHeader(e: io::Error) {
            description("error reading header on incoming tcp connection")
            display("error reading header on incoming tcp connection: {}", e)
            cause(e)
        }
        EchoAddress(e: RendezvousServerError) {
            description("error sending echo address response")
            display("error sending echo address response: {}", e)
            cause(e)
        }
    }
}

impl PaListener {
    #[cfg(test)]
    pub fn bind(addr: &PaAddr, handle: &Handle) -> io::Result<PaListener> {
        match *addr {
            PaAddr::Tcp(ref tcp_addr) => {
                let listener = TcpListener::bind(tcp_addr, handle)?;
                let listener = PaListener::Tcp(listener);
                Ok(listener)
            }
            PaAddr::Utp(ref utp_addr) => {
                let socket = UdpSocket::bind(utp_addr, handle)?;
                let (socket, listener) = UtpSocket::from_socket(socket, handle)?;
                let listener = PaListener::Utp(socket, listener);
                Ok(listener)
            }
        }
    }

    pub fn bind_public(
        addr: &PaAddr,
        handle: &Handle,
        p2p: &P2p,
    ) -> BoxFuture<(PaListener, PaAddr), BindPublicError> {
        match *addr {
            PaAddr::Tcp(ref tcp_addr) => {
                TcpListener::bind_public(tcp_addr, handle, p2p)
                    .map_err(BindPublicError::BindTcp)
                    .map(|(listener, public_addr)| {
                        let listener = PaListener::Tcp(listener);
                        let public_addr = PaAddr::Tcp(public_addr);
                        (listener, public_addr)
                    })
                    .into_boxed()
            }
            PaAddr::Utp(utp_addr) => {
                let handle = handle.clone();
                UdpSocket::bind_public(&utp_addr, &handle, p2p)
                    .map_err(BindPublicError::BindUdp)
                    .and_then(move |(socket, public_addr)| {
                        let (socket, listener) = {
                            UtpSocket::from_socket(socket, &handle).map_err(
                                BindPublicError::MakeUtpSocket,
                            )?
                        };
                        let listener = PaListener::Utp(socket, listener);
                        let public_addr = PaAddr::Utp(public_addr);
                        Ok((listener, public_addr))
                    })
                    .into_boxed()
            }
        }
    }

    pub fn bind_reusable(addr: &PaAddr, handle: &Handle) -> io::Result<PaListener> {
        match *addr {
            PaAddr::Tcp(ref tcp_addr) => {
                let listener = TcpListener::bind_reusable(tcp_addr, handle)?;
                let listener = PaListener::Tcp(listener);
                Ok(listener)
            }
            PaAddr::Utp(ref utp_addr) => {
                let socket = UdpSocket::bind_reusable(utp_addr, handle)?;
                let (socket, listener) = UtpSocket::from_socket(socket, handle)?;
                let listener = PaListener::Utp(socket, listener);
                Ok(listener)
            }
        }
    }

    pub fn expanded_local_addrs(&self) -> io::Result<Vec<PaAddr>> {
        match *self {
            PaListener::Tcp(ref tcp_listener) => {
                let addrs = tcp_listener.expanded_local_addrs()?;
                let addrs = addrs.into_iter().map(PaAddr::Tcp).collect();
                Ok(addrs)
            }
            PaListener::Utp(_, ref utp_listener) => {
                let addr = utp_listener.local_addr()?;
                let addrs = addr.expand_local_unspecified()?;
                let addrs = addrs.into_iter().map(PaAddr::Utp).collect();
                Ok(addrs)
            }
        }
    }

    pub fn local_addr(&self) -> io::Result<PaAddr> {
        match *self {
            PaListener::Tcp(ref tcp_listener) => Ok(PaAddr::Tcp(tcp_listener.local_addr()?)),
            PaListener::Utp(_, ref utp_listener) => Ok(PaAddr::Utp(utp_listener.local_addr()?)),
        }
    }

    pub fn incoming(self) -> PaIncoming {
        match self {
            PaListener::Tcp(tcp_listener) => {
                let incoming = tcp_listener.incoming();
                let processing = FuturesUnordered::new();
                PaIncoming {
                    inner: PaIncomingInner::Tcp {
                        incoming,
                        processing,
                    },
                }
            }
            PaListener::Utp(socket, utp_listener) => {
                let incoming = utp_listener.incoming();
                let raw_rx = socket.raw_receiver();
                let processing = FuturesUnordered::new();
                PaIncoming {
                    inner: PaIncomingInner::Utp {
                        incoming,
                        raw_rx,
                        processing,
                    },
                }
            }
        }
    }
}

impl Stream for PaIncoming {
    type Item = (FramedPaStream, PaAddr);
    type Error = AcceptError;

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, AcceptError> {
        match self.inner {
            PaIncomingInner::Tcp {
                ref mut incoming,
                ref mut processing,
            } => incoming_tcp(incoming, processing),
            PaIncomingInner::Utp {
                ref mut incoming,
                ref mut raw_rx,
                ref mut processing,
            } => incoming_utp(incoming, raw_rx, processing),
        }
    }
}

fn incoming_tcp(
    incoming: &mut tokio_core::net::Incoming,
    processing: &mut FuturesUnordered<BoxFuture<Option<(FramedPaStream, SocketAddr)>, AcceptError>>,
) -> Result<Async<Option<(FramedPaStream, PaAddr)>>, AcceptError> {
    loop {
        match incoming.poll().map_err(AcceptError::TcpAccept)? {
            Async::Ready(Some((stream, addr))) => {
                processing.push(handle_tcp_connection(stream, addr));
            }
            Async::Ready(None) |
            Async::NotReady => break,
        }
    }
    loop {
        match processing.poll()? {
            Async::Ready(Some(Some((stream, addr)))) => {
                let addr = PaAddr::Tcp(addr);
                return Ok(Async::Ready(Some((stream, addr))));
            }
            Async::Ready(Some(None)) => (),
            Async::Ready(None) |
            Async::NotReady => break,
        }
    }
    Ok(Async::NotReady)
}

/// Receives first message from connection and dispatches corresponding action.
fn handle_tcp_connection(
    stream: TcpStream,
    addr: SocketAddr,
) -> BoxFuture<Option<(FramedPaStream, SocketAddr)>, AcceptError> {
    framed_stream(PaStream::Tcp(stream))
        .into_future()
        .map_err(|(err, _stream)| AcceptError::TcpAccept(err))
        .and_then(|(req_opt, stream)| {
            req_opt.map(|req| (req, stream)).ok_or_else(|| {
                AcceptError::TcpReadHeader(io::ErrorKind::ConnectionReset.into())
            })
        })
        .and_then(move |(req, stream)| if req[..] == ECHO_REQ[..] {
            // TODO(povilas): use authenticated crypto context
            let crypto_ctx = p2p::CryptoContext::null();
            tcp_respond_with_addr(stream, addr, &crypto_ctx)
                .map(|_stream| None)
                .map_err(AcceptError::EchoAddress)
                .into_boxed()
        } else if req[..] == CRUST_TCP_INIT[..] {
            future::ok(Some((stream, addr))).into_boxed()
        } else {
            future::err(AcceptError::InvalidTcpHeader).into_boxed()
        })
        .into_boxed()
}

fn incoming_utp(
    incoming: &mut tokio_utp::Incoming,
    raw_rx: &mut tokio_utp::RawReceiver,
    processing: &mut FuturesUnordered<BoxFuture<(), AcceptError>>,
) -> Result<Async<Option<(FramedPaStream, PaAddr)>>, AcceptError> {
    loop {
        match raw_rx.poll().void_unwrap() {
            Async::Ready(Some(raw_channel)) => {
                processing.push({
                    raw_channel
                        .into_future()
                        .map_err(|(v, _raw_channel)| v)
                        .infallible()
                        .and_then(|(bytes, raw_channel)| {
                            let bytes =
                                unwrap!(
                            bytes,
                            "an incoming raw_channel will always have an initial packet to read",
                        );
                            // TODO(povilas): decrypt bytes
                            if ECHO_REQ[..] == bytes[..] {
                                let addr = raw_channel.peer_addr();
                                // TODO(povilas): use authenticated crypto context
                                let crypto_ctx = p2p::CryptoContext::null();
                                udp_respond_with_addr(raw_channel, addr, &crypto_ctx)
                                    .map_err(AcceptError::EchoAddress)
                                    .map(|_raw_channel| ())
                                    .into_boxed()
                            } else {
                                future::err(AcceptError::InvalidUdpHeader).into_boxed()
                            }
                        })
                        .into_boxed()
                });
            }
            Async::Ready(None) |
            Async::NotReady => break,
        }
    }
    loop {
        match processing.poll()? {
            Async::Ready(Some(())) => (),
            Async::Ready(None) |
            Async::NotReady => break,
        }
    }
    match incoming.poll().map_err(AcceptError::UtpAccept)? {
        Async::Ready(Some(stream)) => {
            let addr = PaAddr::Utp(stream.peer_addr());
            let stream = PaStream::Utp(stream);
            Ok(Async::Ready(Some((framed_stream(stream), addr))))
        }
        Async::Ready(None) => Ok(Async::Ready(None)),
        Async::NotReady => Ok(Async::NotReady),
    }
}
