// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::net::protocol_agnostic::{ListenerMsg, ListenerMsgKind};
use crate::priv_prelude::*;
use futures::stream::FuturesUnordered;
use p2p::{self, P2p};
use tokio_core;
use tokio_io::codec::length_delimited::Framed;
use tokio_utp;

/// When `PaListener` accepts incoming connection, the connection must send `ListenerMsg` within
/// this timeout.
const LISTENER_MSG_TIMEOUT: u64 = 10;

/// A convenient wrapper around uTP and TCP connection listeners.
#[derive(Debug)]
pub struct PaListener {
    handle: Handle,
    inner: PaListenerInner,
    our_sk: SecretEncryptKey,
    our_pk: PublicEncryptKey,
}

#[derive(Debug)]
pub enum PaListenerInner {
    Tcp(TcpListener),
    Utp(UtpSocket, UtpListener),
}

pub struct PaIncoming {
    handle: Handle,
    inner: PaIncomingInner,
    our_sk: SecretEncryptKey,
    our_pk: PublicEncryptKey,
    processing: FuturesUnordered<BoxFuture<Option<PaStream>, AcceptError>>,
}

enum PaIncomingInner {
    Tcp(tokio_core::net::Incoming),
    Utp(tokio_utp::Incoming),
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
        Read(e: io::Error) {
            description("error reading the incoming stream")
            display("error reading the incoming stream: {}", e)
            cause(e)
        }
        Write(e: io::Error) {
            description("error writing to the incoming stream")
            display("error writing to the incoming stream: {}", e)
            cause(e)
        }
        Disconnected {
            description("remote peer disconnected")
        }
        Timeout {
            description("timeout waiting for message from remote peer")
        }
        Decrypt(e: EncryptionError) {
            description("error decrypting message from remote peer")
            display("error decrypting message from remote peer: {}", e)
            cause(e)
        }
        Encrypt(e: EncryptionError) {
            description("error encrypting message to send to remote peer")
            display("error encrypting message to send to remote peer: {}", e)
            cause(e)
        }
    }
}

impl PaListener {
    #[cfg(test)]
    pub fn bind(
        addr: &PaAddr,
        handle: &Handle,
        our_sk: SecretEncryptKey,
        our_pk: PublicEncryptKey,
    ) -> io::Result<PaListener> {
        match *addr {
            PaAddr::Tcp(ref tcp_addr) => {
                let listener = TcpListener::bind(tcp_addr, handle)?;
                let listener = PaListenerInner::Tcp(listener);
                Ok(Self {
                    handle: handle.clone(),
                    inner: listener,
                    our_sk,
                    our_pk,
                })
            }
            PaAddr::Utp(ref utp_addr) => {
                let socket = UdpSocket::bind(utp_addr, handle)?;
                let (socket, listener) = UtpSocket::from_socket(socket, handle)?;
                let listener = PaListenerInner::Utp(socket, listener);
                Ok(Self {
                    handle: handle.clone(),
                    inner: listener,
                    our_sk,
                    our_pk,
                })
            }
        }
    }

    pub fn bind_public(
        addr: &PaAddr,
        handle: &Handle,
        p2p: &P2p,
        our_sk: SecretEncryptKey,
        our_pk: PublicEncryptKey,
    ) -> BoxFuture<(PaListener, PaAddr), BindPublicError> {
        let handle = handle.clone();
        match *addr {
            PaAddr::Tcp(ref tcp_addr) => TcpListener::bind_public(tcp_addr, &handle, p2p)
                .map_err(BindPublicError::BindTcp)
                .map(move |(listener, public_addr)| {
                    let listener = Self {
                        handle,
                        inner: PaListenerInner::Tcp(listener),
                        our_sk,
                        our_pk,
                    };
                    let public_addr = PaAddr::Tcp(public_addr);
                    (listener, public_addr)
                })
                .into_boxed(),
            PaAddr::Utp(utp_addr) => UdpSocket::bind_public(&utp_addr, &handle, p2p)
                .map_err(BindPublicError::BindUdp)
                .and_then(move |(socket, public_addr)| {
                    let (socket, listener) = {
                        UtpSocket::from_socket(socket, &handle)
                            .map_err(BindPublicError::MakeUtpSocket)?
                    };
                    let listener = Self {
                        handle,
                        inner: PaListenerInner::Utp(socket, listener),
                        our_sk,
                        our_pk,
                    };
                    let public_addr = PaAddr::Utp(public_addr);
                    Ok((listener, public_addr))
                })
                .into_boxed(),
        }
    }

    pub fn bind_reusable(
        addr: &PaAddr,
        handle: &Handle,
        our_sk: SecretEncryptKey,
        our_pk: PublicEncryptKey,
    ) -> io::Result<PaListener> {
        match *addr {
            PaAddr::Tcp(ref tcp_addr) => {
                let listener = TcpListener::bind_reusable(tcp_addr, handle)?;
                let listener = Self {
                    handle: handle.clone(),
                    inner: PaListenerInner::Tcp(listener),
                    our_sk,
                    our_pk,
                };
                Ok(listener)
            }
            PaAddr::Utp(ref utp_addr) => {
                let socket = UdpSocket::bind_reusable(utp_addr, handle)?;
                let (socket, listener) = UtpSocket::from_socket(socket, handle)?;
                let listener = Self {
                    handle: handle.clone(),
                    inner: PaListenerInner::Utp(socket, listener),
                    our_sk,
                    our_pk,
                };
                Ok(listener)
            }
        }
    }

    pub fn expanded_local_addrs(&self) -> io::Result<Vec<PaAddr>> {
        match self.inner {
            PaListenerInner::Tcp(ref tcp_listener) => {
                let addrs = tcp_listener.expanded_local_addrs()?;
                let addrs = addrs.into_iter().map(PaAddr::Tcp).collect();
                Ok(addrs)
            }
            PaListenerInner::Utp(_, ref utp_listener) => {
                let addr = utp_listener.local_addr()?;
                let addrs = addr.expand_local_unspecified()?;
                let addrs = addrs.into_iter().map(PaAddr::Utp).collect();
                Ok(addrs)
            }
        }
    }

    pub fn local_addr(&self) -> io::Result<PaAddr> {
        match self.inner {
            PaListenerInner::Tcp(ref tcp_listener) => Ok(PaAddr::Tcp(tcp_listener.local_addr()?)),
            PaListenerInner::Utp(_, ref utp_listener) => {
                Ok(PaAddr::Utp(utp_listener.local_addr()?))
            }
        }
    }

    pub fn incoming(self) -> PaIncoming {
        let inner = match self.inner {
            PaListenerInner::Tcp(tcp_listener) => PaIncomingInner::Tcp(tcp_listener.incoming()),
            PaListenerInner::Utp(_socket, utp_listener) => {
                PaIncomingInner::Utp(utp_listener.incoming())
            }
        };
        PaIncoming {
            handle: self.handle,
            inner,
            processing: FuturesUnordered::new(),
            our_sk: self.our_sk,
            our_pk: self.our_pk,
        }
    }
}

impl Stream for PaIncoming {
    type Item = PaStream;
    type Error = AcceptError;

    fn poll(&mut self) -> Result<Async<Option<PaStream>>, AcceptError> {
        match self.inner {
            PaIncomingInner::Tcp(ref mut incoming) => loop {
                match incoming.poll().map_err(AcceptError::TcpAccept)? {
                    Async::Ready(Some((stream, addr))) => {
                        self.processing.push(handle_incoming_tcp(
                            &self.handle,
                            stream,
                            addr,
                            &self.our_sk,
                            &self.our_pk,
                        ));
                    }
                    Async::Ready(None) | Async::NotReady => break,
                }
            },
            PaIncomingInner::Utp(ref mut incoming) => loop {
                match incoming.poll().map_err(AcceptError::UtpAccept)? {
                    Async::Ready(Some(stream)) => {
                        self.processing.push(handle_incoming_utp(
                            &self.handle,
                            stream,
                            &self.our_sk,
                            &self.our_pk,
                        ));
                    }
                    Async::Ready(None) | Async::NotReady => break,
                }
            },
        }
        loop {
            match self.processing.poll()? {
                Async::Ready(Some(Some(x))) => return Ok(Async::Ready(Some(x))),
                Async::Ready(Some(None)) => continue,
                Async::Ready(None) | Async::NotReady => break Ok(Async::NotReady),
            }
        }
    }
}

fn handle_incoming_tcp(
    handle: &Handle,
    stream: TcpStream,
    addr: SocketAddr,
    our_sk: &SecretEncryptKey,
    our_pk: &PublicEncryptKey,
) -> BoxFuture<Option<PaStream>, AcceptError> {
    handle_incoming(handle, stream, addr, our_sk, our_pk)
        .map(|framed_key_opt| {
            framed_key_opt.map(move |(framed, shared_secret)| {
                PaStream::from_framed_tcp_stream(framed, shared_secret)
            })
        })
        .into_boxed()
}

fn handle_incoming_utp(
    handle: &Handle,
    stream: UtpStream,
    our_sk: &SecretEncryptKey,
    our_pk: &PublicEncryptKey,
) -> BoxFuture<Option<PaStream>, AcceptError> {
    let addr = stream.peer_addr();
    handle_incoming(handle, stream, addr, our_sk, our_pk)
        .map(|framed_key_opt| {
            framed_key_opt.map(move |(framed, shared_secret)| {
                PaStream::from_framed_utp_stream(framed, shared_secret)
            })
        })
        .into_boxed()
}

fn handle_incoming<S: AsyncRead + AsyncWrite + 'static>(
    handle: &Handle,
    stream: S,
    addr: SocketAddr,
    our_sk: &SecretEncryptKey,
    our_pk: &PublicEncryptKey,
) -> BoxFuture<Option<(Framed<S>, SharedSecretKey)>, AcceptError> {
    let our_sk = our_sk.clone();
    let our_pk = *our_pk;
    Framed::new(stream)
        .into_future()
        .map_err(|(e, _framed)| AcceptError::Read(e))
        .and_then(|(msg_opt, framed)| {
            msg_opt
                .ok_or(AcceptError::Disconnected)
                .map(|msg| (msg, framed))
        })
        .with_timeout(Duration::from_secs(LISTENER_MSG_TIMEOUT), handle)
        .and_then(|pair_opt| pair_opt.ok_or(AcceptError::Timeout))
        .and_then(move |(msg, framed)| {
            let req: ListenerMsg = try_bfut!(our_sk
                .anonymously_decrypt(&msg, &our_pk)
                .map_err(AcceptError::Decrypt));
            let shared_secret = our_sk.shared_secret(&req.client_pk);
            match req.kind {
                ListenerMsgKind::EchoAddr => {
                    let msg = BytesMut::from(try_bfut!(shared_secret
                        .encrypt(&addr)
                        .map_err(AcceptError::Encrypt)));
                    framed
                        .send(msg)
                        .map_err(AcceptError::Write)
                        .map(|_framed| None)
                        .into_boxed()
                }
                ListenerMsgKind::Connect => future::ok(Some((framed, shared_secret))).into_boxed(),
            }
        })
        .into_boxed()
}
