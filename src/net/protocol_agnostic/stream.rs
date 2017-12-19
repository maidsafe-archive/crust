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

use bincode::{self, Infinite};
use future_utils::bi_channel;
use futures::future::Either;
use futures::sync::mpsc::SendError;
use p2p::P2p;
use priv_prelude::*;
use std::error::Error;
use std::io::{Read, Write};
use tokio_io::{AsyncRead, AsyncWrite};
use void;

#[derive(Debug)]
pub enum PaStream {
    Tcp(TcpStream),
    Utp(UtpStream),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaRendezvousMsg {
    pub tcp: Option<Bytes>,
    pub utp: Option<Bytes>,
}

impl PaStream {
    pub fn from_tcp_stream(stream: TcpStream) -> PaStream {
        PaStream::Tcp(stream)
    }

    pub fn from_utp_stream(stream: UtpStream) -> PaStream {
        PaStream::Utp(stream)
    }

    pub fn direct_connect(
        addr: &PaAddr,
        handle: &Handle,
        config: &ConfigFile,
    ) -> IoFuture<PaStream> {
        let disable_tcp = match config.read().dev {
            Some(ref dev) => dev.disable_tcp,
            None => false,
        };

        match *addr {
            PaAddr::Tcp(ref tcp_addr) => {
                if disable_tcp {
                    future::err(io::Error::new(io::ErrorKind::Other, "tcp disabled"))
                        .into_boxed()
                } else {
                    TcpStream::connect(tcp_addr, handle)
                        .map(PaStream::Tcp)
                        .into_boxed()
                }
            }
            PaAddr::Utp(utp_addr) => {
                UtpSocket::bind(&addr!("0.0.0.0:0"), handle)
                    .into_future()
                    .and_then(move |(socket, _listener)| {
                        socket.connect(&utp_addr).map(PaStream::Utp)
                    })
                    .into_boxed()
            }
        }
    }

    pub fn rendezvous_connect<C>(
        channel: C,
        handle: &Handle,
        config: &ConfigFile,
        p2p: &P2p,
    ) -> BoxFuture<PaStream, PaRendezvousConnectError<C::Error, C::SinkError>>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static,
    {
        let disable_tcp = match config.read().dev {
            Some(ref dev) => dev.disable_tcp,
            None => false,
        };

        let (tcp_ch_0, tcp_ch_1) = bi_channel::unbounded();
        let (utp_ch_0, utp_ch_1) = bi_channel::unbounded();

        let pump_channels = {
            tcp_ch_0
                .into_future()
                .map_err(|(v, _)| void::unreachable(v))
                .and_then(move |(tcp_msg_opt, tcp_ch_0)| {
                    utp_ch_0
                        .into_future()
                        .map_err(|(v, _)| void::unreachable(v))
                        .and_then(move |(utp_msg_opt, utp_ch_0)| {
                            let msg = PaRendezvousMsg {
                                tcp: if disable_tcp { None } else { tcp_msg_opt },
                                utp: utp_msg_opt,
                            };
                            let msg = unwrap!(bincode::serialize(&msg, Infinite));
                            let msg = Bytes::from(msg);
                            channel
                                .send(msg)
                                .map_err(PaRendezvousConnectError::ChannelWrite)
                                .and_then(|channel| {
                                    channel.into_future().map_err(|(err, _channel)| {
                                        PaRendezvousConnectError::ChannelRead(err)
                                    })
                                })
                                .and_then(move |(msg_opt, _channel)| {
                                    if let Some(msg) = msg_opt {
                                        let msg: PaRendezvousMsg = {
                                bincode::deserialize(&msg)
                                .map_err(PaRendezvousConnectError::DeserializeMsg)?
                            };
                                        if let Some(tcp) = msg.tcp {
                                            if !disable_tcp {
                                                let _ = tcp_ch_0.unbounded_send(tcp);
                                            }
                                        }
                                        if let Some(utp) = msg.utp {
                                            let _ = utp_ch_0.unbounded_send(utp);
                                        }
                                    }
                                    Ok(())
                                })
                        })
                })
        };

        let connect = {
            let handle = handle.clone();
            let tcp_connect = {
                TcpStream::rendezvous_connect(tcp_ch_1, &handle, p2p).map(PaStream::Tcp)
            };
            let utp_connect = {
                UdpSocket::rendezvous_connect(utp_ch_1, &handle, p2p)
                    .map_err(UtpRendezvousConnectError::Rendezvous)
                    .and_then(move |(udp_socket, addr)| {
                        let (utp_socket, _utp_listener) = {
                            UtpSocket::from_socket(udp_socket, &handle).map_err(
                                UtpRendezvousConnectError::IntoUtpSocket,
                            )?
                        };
                        Ok((utp_socket, addr))
                    })
                    .and_then(|(utp_socket, addr)| {
                        utp_socket
                            .connect(&addr)
                            .map_err(UtpRendezvousConnectError::UtpConnect)
                            .map(PaStream::Utp)
                    })
            };

            tcp_connect
                .select2(utp_connect)
                .map(|either| match either {
                    Either::A((stream, _)) |
                    Either::B((stream, _)) => stream,
                })
                .or_else(|either| match either {
                    Either::A((tcp_error, udp_connect)) => {
                        udp_connect
                            .map_err(move |utp_error| {
                                PaRendezvousConnectError::AllProtocolsFailed {
                                    tcp: Box::new(tcp_error),
                                    utp: Box::new(utp_error),
                                }
                            })
                            .into_boxed()
                    }
                    Either::B((utp_error, tcp_connect)) => {
                        tcp_connect
                            .map_err(move |tcp_error| {
                                PaRendezvousConnectError::AllProtocolsFailed {
                                    tcp: Box::new(tcp_error),
                                    utp: Box::new(utp_error),
                                }
                            })
                            .into_boxed()
                    }
                })
        };

        let ret = {
            pump_channels
                .select2(connect)
                .map_err(|either| match either {
                    Either::A((err, _)) |
                    Either::B((err, _)) => err,
                })
                .and_then(|either| match either {
                    Either::A(((), connect)) => connect.into_boxed(),
                    Either::B((stream, _)) => future::ok(stream).into_boxed(),
                })
        };

        ret.into_boxed()
    }

    pub fn peer_addr(&self) -> io::Result<PaAddr> {
        match *self {
            PaStream::Tcp(ref stream) => Ok(PaAddr::Tcp(stream.peer_addr()?)),
            PaStream::Utp(ref stream) => Ok(PaAddr::Utp(stream.peer_addr())),
        }
    }
}

impl Read for PaStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            PaStream::Tcp(ref mut stream) => stream.read(buf),
            PaStream::Utp(ref mut stream) => stream.read(buf),
        }
    }
}

impl Write for PaStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            PaStream::Tcp(ref mut stream) => stream.write(buf),
            PaStream::Utp(ref mut stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            PaStream::Tcp(ref mut stream) => stream.flush(),
            PaStream::Utp(ref mut stream) => stream.flush(),
        }
    }
}

impl AsyncRead for PaStream {}

impl AsyncWrite for PaStream {
    fn shutdown(&mut self) -> io::Result<Async<()>> {
        match *self {
            PaStream::Tcp(ref mut stream) => stream.shutdown(),
            PaStream::Utp(ref mut stream) => stream.shutdown(),
        }
    }
}

#[derive(Debug)]
pub enum UtpRendezvousConnectError<Ei, Eo> {
    Rendezvous(UdpRendezvousConnectError<Ei, Eo>),
    IntoUtpSocket(io::Error),
    UtpConnect(io::Error),
}

impl<Ei, Eo> fmt::Display for UtpRendezvousConnectError<Ei, Eo>
where
    Ei: Error,
    Eo: Error,
{
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use self::UtpRendezvousConnectError::*;
        match *self {
            Rendezvous(ref e) => write!(formatter, "udp rendezvous failed: {}", e),
            IntoUtpSocket(ref e) => write!(formatter, "failed to init utp socket: {}", e),
            UtpConnect(ref e) => write!(formatter, "utp connect failed: {}", e),
        }
    }
}

impl<Ei, Eo> Error for UtpRendezvousConnectError<Ei, Eo>
where
    Ei: Error,
    Eo: Error,
{
    fn description(&self) -> &str {
        use self::UtpRendezvousConnectError::*;
        match *self {
            Rendezvous(..) => "udp rendezvous failed",
            IntoUtpSocket(..) => "failed to init utp socket",
            UtpConnect(..) => "utp connect failed",
        }
    }

    fn cause(&self) -> Option<&Error> {
        use self::UtpRendezvousConnectError::*;
        match *self {
            Rendezvous(ref e) => Some(e),
            IntoUtpSocket(ref e) => Some(e),
            UtpConnect(ref e) => Some(e),
        }
    }
}

#[derive(Debug)]

pub enum PaRendezvousConnectError<Ei, Eo> {
    ChannelWrite(Eo),
    ChannelRead(Ei),
    DeserializeMsg(bincode::Error),
    AllProtocolsFailed {
        tcp: Box<TcpRendezvousConnectError<Void, SendError<Bytes>>>,
        utp: Box<UtpRendezvousConnectError<Void, SendError<Bytes>>>,
    },
}

impl<Ei, Eo> fmt::Display for PaRendezvousConnectError<Ei, Eo>
where
    Ei: fmt::Display,
    Eo: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PaRendezvousConnectError::ChannelWrite(ref e) => {
                write!(formatter, "error writing to rendezvous channel: {}", e)
            }
            PaRendezvousConnectError::ChannelRead(ref e) => {
                write!(formatter, "error reading from rendezvous channel: {}", e)
            }
            PaRendezvousConnectError::DeserializeMsg(ref e) => {
                write!(
                    formatter,
                    "error deserializing message from rendezvous channel: {}",
                    e
                )
            }
            PaRendezvousConnectError::AllProtocolsFailed { ref tcp, ref utp } => {
                write!(
                    formatter,
                    "all rendezvous connect protocols failed. tcp error: {}; utp error: {}",
                    tcp, utp,
                )
            }
        }
    }
}

impl<Ei, Eo> Error for PaRendezvousConnectError<Ei, Eo>
where
    Ei: Error,
    Eo: Error,
{
    fn description(&self) -> &str {
        match *self {
            PaRendezvousConnectError::ChannelWrite(..) => "error writing to rendezvous channel",
            PaRendezvousConnectError::ChannelRead(..) => "error reading from rendezvous channel",
            PaRendezvousConnectError::DeserializeMsg(..) => {
                "error deserializing message from rendezvous channel"
            }
            PaRendezvousConnectError::AllProtocolsFailed { .. } => {
                "all rendezvous connect protocols failed"
            }
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            PaRendezvousConnectError::ChannelWrite(ref e) => Some(e),
            PaRendezvousConnectError::ChannelRead(ref e) => Some(e),
            PaRendezvousConnectError::DeserializeMsg(ref e) => Some(e),
            PaRendezvousConnectError::AllProtocolsFailed { .. } => None,
        }
    }
}
