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
use futures::sync::mpsc::SendError;
use net::protocol_agnostic::CRUST_TCP_INIT;
use p2p::P2p;
use priv_prelude::*;
use rust_sodium::crypto;
use std::error::Error;
use std::io::{Read, Write};
use tokio_io::{self, AsyncRead, AsyncWrite};
use tokio_io::codec::length_delimited::{self, Framed};
use void;

/// The maximum size of packets sent by `PaStream` in bytes.
const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;
const MAX_HEADER_SIZE: usize = 8;

/// Converts given stream into length delimited framed stream.
/// This stream takes care of deconstructing messages and spits `BytesMut` with exactly the
/// same amount of bytes as were sent.
pub fn framed_stream<T>(stream: T) -> Framed<T>
where
    T: AsyncRead + AsyncWrite,
{
    length_delimited::Builder::new()
        .max_frame_length(MAX_PAYLOAD_SIZE + MAX_HEADER_SIZE)
        .new_framed(stream)
}

/// Protocol agnostic stream that yields length delimited frames of `BytesMut`.
pub type FramedPaStream = Framed<PaStream, BytesMut>;

#[derive(Debug)]
pub enum PaStream {
    Tcp(TcpStream),
    Utp(UtpStream),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaRendezvousMsg {
    pub enc_pk: crypto::box_::PublicKey,
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
    ) -> IoFuture<(Framed<PaStream>, PaAddr)> {
        let disable_tcp = config.tcp_disabled();

        match *addr {
            PaAddr::Tcp(ref tcp_addr) => {
                if disable_tcp {
                    future::err(io::Error::new(io::ErrorKind::Other, "tcp disabled")).into_boxed()
                } else {
                    TcpStream::connect(tcp_addr, handle)
                        .and_then(|stream| {
                            let peer_addr = stream.peer_addr()?;
                            Ok((PaStream::Tcp(stream), PaAddr::Tcp(peer_addr)))
                        })
                        .and_then(|(stream, peer_addr)| {
                            framed_stream(stream)
                                .send(BytesMut::from(&CRUST_TCP_INIT[..]))
                                .map(move |stream| (stream, peer_addr))
                        })
                        .into_boxed()
                }
            }
            PaAddr::Utp(utp_addr) => {
                UtpSocket::bind(&addr!("0.0.0.0:0"), handle)
                    .into_future()
                    .and_then(move |(socket, _listener)| {
                        socket.connect(&utp_addr).map(PaStream::Utp)
                    })
                    .and_then(|stream| {
                        let peer_addr = stream.peer_addr()?;
                        Ok((framed_stream(stream), peer_addr))
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
        let disable_tcp = config.tcp_disabled();

        let (tcp_ch_0, tcp_ch_1) = bi_channel::unbounded();
        let (utp_ch_0, utp_ch_1) = bi_channel::unbounded();

        let (our_pk, _sk) = crypto::box_::gen_keypair();
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
                                enc_pk: our_pk,
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
                                .and_then(move |(msg_opt, _channel)| if let Some(msg) = msg_opt {
                                    let msg: PaRendezvousMsg = {
                                        bincode::deserialize(&msg).map_err(
                                            PaRendezvousConnectError::DeserializeMsg,
                                        )?
                                    };
                                    if let Some(tcp) = msg.tcp {
                                        if !disable_tcp {
                                            let _ = tcp_ch_0.unbounded_send(tcp);
                                        }
                                    }
                                    if let Some(utp) = msg.utp {
                                        let _ = utp_ch_0.unbounded_send(utp);
                                    }
                                    let their_pk = msg.enc_pk;
                                    Ok(their_pk)
                                } else {
                                    Err(PaRendezvousConnectError::ChannelClosed)
                                })
                        })
                })
        };

        let handle = handle.clone();
        let tcp_connect = {
            TcpStream::rendezvous_connect(tcp_ch_1, &handle, p2p).map(PaStream::Tcp)
        };
        let udp_connect = {
            UdpSocket::rendezvous_connect(utp_ch_1, &handle, p2p)
                .map_err(UtpRendezvousConnectError::Rendezvous)
                .and_then(move |(udp_socket, addr)| {
                    trace!("udp rendezvous connect succeeded.");
                    let (utp_socket, utp_listener) = {
                        UtpSocket::from_socket(udp_socket, &handle).map_err(
                            UtpRendezvousConnectError::IntoUtpSocket,
                        )?
                    };
                    trace!("returning utp socket.");
                    Ok((utp_socket, utp_listener, addr))
                })
        };

        let ret = {
            pump_channels
                .while_driving(tcp_connect)
                .while_driving(udp_connect)
                .map_err(|((e, _tcp_connect), _udp_connect)| e)
                .and_then(move |((their_pk, tcp_connect), udp_connect)| if our_pk >
                    their_pk
                {
                    let utp_connect = {
                        udp_connect.and_then(|(utp_socket, _utp_listener, addr)| {
                            utp_socket
                                .connect(&addr)
                                .map_err(UtpRendezvousConnectError::UtpConnect)
                                .map(PaStream::Utp)
                        })
                    };
                    let connect = {
                        tcp_connect.first_ok2(utp_connect).map_err(
                            |(tcp_err, utp_err)| {
                                PaRendezvousConnectError::AllProtocolsFailed {
                                    tcp: Box::new(tcp_err),
                                    utp: Box::new(utp_err),
                                }
                            },
                        )
                    };
                    connect
                        .and_then(|stream| {
                            tokio_io::io::write_all(stream, b"CHOOSE").map_err(
                                PaRendezvousConnectError::SendChoose,
                            )
                        })
                        .map(|(stream, _buf)| stream)
                        .into_boxed()
                } else {
                    let tcp_connect = tcp_connect.map(take_chosen);
                    let utp_connect = {
                        udp_connect
                            .and_then(|(_utp_socket, utp_listener, addr)| {
                                utp_listener
                                    .incoming()
                                    .filter(move |stream| stream.peer_addr() == addr)
                                    .first_ok()
                                    .map(PaStream::Utp)
                                    .map_err(UtpRendezvousConnectError::UtpAccept)
                            })
                            .map(take_chosen)
                    };
                    let connect = {
                        tcp_connect
                            .first_ok2(utp_connect)
                            .map_err(|(tcp_err, utp_err)| {
                                PaRendezvousConnectError::AllProtocolsFailed {
                                    tcp: Box::new(tcp_err),
                                    utp: Box::new(utp_err),
                                }
                            })
                            .and_then(|res| res)
                    };

                    connect.into_boxed()
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

fn take_chosen<Ei: 'static, Eo: 'static>(
    stream: PaStream,
) -> BoxFuture<PaStream, PaRendezvousConnectError<Ei, Eo>> {
    tokio_io::io::read_exact(stream, [0u8; 6])
        .map_err(PaRendezvousConnectError::ReadStream)
        .and_then(|(stream, buff)| if &buff == b"CHOOSE" {
            Ok(stream)
        } else {
            Err(PaRendezvousConnectError::ExpectedChoose)
        })
        .into_boxed()
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
    UtpAccept(Vec<io::Error>),
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
            UtpAccept(ref es) => {
                write!(formatter, "utp accept failed with {} errors:", es.len())?;
                for (i, e) in es.iter().enumerate() {
                    write!(formatter, " [{} of {}] {};", i, es.len(), e)?;
                }
                Ok(())
            }
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
            UtpAccept(..) => "utp accept failed",
        }
    }

    fn cause(&self) -> Option<&Error> {
        use self::UtpRendezvousConnectError::*;
        match *self {
            Rendezvous(ref e) => Some(e),
            IntoUtpSocket(ref e) |
            UtpConnect(ref e) => Some(e),
            UtpAccept(ref es) => {
                match es.first() {
                    Some(e) => Some(e),
                    None => None,
                }
            }
        }
    }
}

#[derive(Debug)]

pub enum PaRendezvousConnectError<Ei, Eo> {
    ChannelWrite(Eo),
    ChannelRead(Ei),
    ChannelClosed,
    DeserializeMsg(bincode::Error),
    AllProtocolsFailed {
        tcp: Box<TcpRendezvousConnectError<Void, SendError<Bytes>>>,
        utp: Box<UtpRendezvousConnectError<Void, SendError<Bytes>>>,
    },
    ReadStream(io::Error),
    ExpectedChoose,
    SendChoose(io::Error),
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
            PaRendezvousConnectError::ChannelClosed => {
                write!(formatter, "rendezvous channel closed unexpectedly")
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
            PaRendezvousConnectError::ReadStream(ref e) => {
                write!(
                    formatter,
                    "error reading from connected stream: {}",
                    e,
                )
            }
            PaRendezvousConnectError::ExpectedChoose => {
                write!(
                    formatter,
                    "protocol error - peer did not send choose message.",
                )
            }
            PaRendezvousConnectError::SendChoose(ref e) => {
                write!(
                    formatter,
                    "failed to write choose message to stream: {}",
                    e,
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
            PaRendezvousConnectError::ChannelClosed => "rendezvous channel closed unexpectedly",
            PaRendezvousConnectError::DeserializeMsg(..) => {
                "error deserializing message from rendezvous channel"
            }
            PaRendezvousConnectError::AllProtocolsFailed { .. } => {
                "all rendezvous connect protocols failed"
            }
            PaRendezvousConnectError::ReadStream(..) => "error reading from connected stream",
            PaRendezvousConnectError::ExpectedChoose => {
                "protocol error - peer did not send choose message."
            }
            PaRendezvousConnectError::SendChoose(..) => "failed to write choose message to stream",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            PaRendezvousConnectError::ChannelWrite(ref e) => Some(e),
            PaRendezvousConnectError::ChannelRead(ref e) => Some(e),
            PaRendezvousConnectError::DeserializeMsg(ref e) => Some(e),
            PaRendezvousConnectError::ReadStream(ref e) |
            PaRendezvousConnectError::SendChoose(ref e) => Some(e),
            PaRendezvousConnectError::AllProtocolsFailed { .. } |
            PaRendezvousConnectError::ExpectedChoose |
            PaRendezvousConnectError::ChannelClosed => None,
        }
    }
}

#[cfg(test)]
mod test {
    use config::DevConfigSettings;
    use future_utils::bi_channel;
    use priv_prelude::*;
    use tokio_core::reactor::Core;

    #[test]
    fn direct_connect_with_tcp_disabled_connects_but_doesnt_use_tcp() {
        let config = unwrap!(ConfigFile::new_temporary());
        unwrap!(config.write()).dev = Some(DevConfigSettings {
            disable_tcp: true,
            ..Default::default()
        });

        let (ch0, ch1) = bi_channel::unbounded();

        let p2p = P2p::default();
        let mut core = unwrap!(Core::new());
        let handle = core.handle();
        let r = core.run({
            let connect0 = PaStream::rendezvous_connect(ch0, &handle, &config, &p2p);
            let connect1 = PaStream::rendezvous_connect(ch1, &handle, &config, &p2p);
            connect0
                .join(connect1)
                .map_err(|e| panic!("connect failed: {}", e))
                .map(|(stream0, stream1)| {
                    let addr0 = unwrap!(stream0.peer_addr());
                    let addr1 = unwrap!(stream1.peer_addr());
                    assert!(!addr0.is_tcp());
                    assert!(!addr1.is_tcp());
                })
        });
        unwrap!(r)
    }
}
