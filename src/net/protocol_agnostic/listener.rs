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

use p2p;
use priv_prelude::*;
use tokio_core;
use tokio_utp;

#[derive(Debug)]
pub enum PaListener {
    Tcp(TcpListener),
    Utp(UtpListener),
}

pub enum PaIncoming {
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
                let (_, listener) = UtpSocket::from_socket(socket, handle)?;
                let listener = PaListener::Utp(listener);
                Ok(listener)
            }
        }
    }

    pub fn bind_public(
        addr: &PaAddr,
        handle: &Handle,
    ) -> BoxFuture<(PaListener, PaAddr), BindPublicError> {
        match *addr {
            PaAddr::Tcp(ref tcp_addr) => {
                TcpListener::bind_public(tcp_addr, handle)
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
                UdpSocket::bind_public(&utp_addr, &handle)
                    .map_err(BindPublicError::BindUdp)
                    .and_then(move |(socket, public_addr)| {
                        let (_, listener) = {
                            UtpSocket::from_socket(socket, &handle).map_err(
                                BindPublicError::MakeUtpSocket,
                            )?
                        };
                        let listener = PaListener::Utp(listener);
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
                let (_, listener) = UtpSocket::from_socket(socket, handle)?;
                let listener = PaListener::Utp(listener);
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
            PaListener::Utp(ref utp_listener) => {
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
            PaListener::Utp(ref utp_listener) => Ok(PaAddr::Utp(utp_listener.local_addr()?)),
        }
    }

    pub fn incoming(self) -> PaIncoming {
        match self {
            PaListener::Tcp(tcp_listener) => PaIncoming::Tcp(tcp_listener.incoming()),
            PaListener::Utp(utp_listener) => PaIncoming::Utp(utp_listener.incoming()),
        }
    }
}

impl Stream for PaIncoming {
    type Item = (PaStream, PaAddr);
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<Option<(PaStream, PaAddr)>>> {
        match *self {
            PaIncoming::Tcp(ref mut incoming) => {
                match incoming.poll()? {
                    Async::Ready(Some((stream, addr))) => {
                        let stream = PaStream::Tcp(stream);
                        let addr = PaAddr::Tcp(addr);
                        Ok(Async::Ready(Some((stream, addr))))
                    }
                    Async::Ready(None) => Ok(Async::Ready(None)),
                    Async::NotReady => Ok(Async::NotReady),
                }
            }
            PaIncoming::Utp(ref mut incoming) => {
                match incoming.poll()? {
                    Async::Ready(Some(stream)) => {
                        let addr = PaAddr::Utp(stream.peer_addr());
                        let stream = PaStream::Utp(stream);
                        Ok(Async::Ready(Some((stream, addr))))
                    }
                    Async::Ready(None) => Ok(Async::Ready(None)),
                    Async::NotReady => Ok(Async::NotReady),
                }
            }
        }
    }
}
