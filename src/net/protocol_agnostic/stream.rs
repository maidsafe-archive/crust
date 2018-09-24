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

use future_utils::bi_channel;
use futures::sync::mpsc::SendError;
use maidsafe_utilities::serialisation;
use net::protocol_agnostic::{ListenerMsg, ListenerMsgKind};
use p2p::P2p;
use priv_prelude::*;
use std::error::Error;
use tokio_io;
use tokio_io::codec::length_delimited::Framed;
use tokio_io::{AsyncRead, AsyncWrite};
use void;

#[derive(Debug)]
pub struct PaStream {
    inner: PaStreamInner,
    shared_secret: SharedSecretKey,
}

#[derive(Debug)]
enum PaStreamInner {
    Tcp(Framed<TcpStream>),
    Utp(Framed<UtpStream>),
    #[cfg(test)]
    Mem(Framed<memstream::EchoStream>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaRendezvousMsg {
    pub enc_pk: PublicEncryptKey,
    pub tcp: Option<Bytes>,
    pub utp: Option<Bytes>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChooseMsg;

impl PaStream {
    pub fn from_framed_tcp_stream(
        framed: Framed<TcpStream>,
        shared_secret: SharedSecretKey,
    ) -> PaStream {
        PaStream {
            inner: PaStreamInner::Tcp(framed),
            shared_secret,
        }
    }

    pub fn from_framed_utp_stream(
        framed: Framed<UtpStream>,
        shared_secret: SharedSecretKey,
    ) -> PaStream {
        PaStream {
            inner: PaStreamInner::Utp(framed),
            shared_secret,
        }
    }

    #[cfg(test)]
    /// Construct protocol agnostic stream with the in-memory backend stream.
    /// Convenient for testing.
    pub fn from_framed_mem_stream(
        framed: Framed<memstream::EchoStream>,
        shared_secret: SharedSecretKey,
    ) -> PaStream {
        PaStream {
            inner: PaStreamInner::Mem(framed),
            shared_secret,
        }
    }

    /// Gracefully terminates connection.
    pub fn finalize(self) -> IoFuture<()> {
        match self.inner {
            PaStreamInner::Tcp(tcp_stream) => tokio_io::io::shutdown(tcp_stream.into_inner())
                .map(|_stream| ())
                .into_boxed(),
            PaStreamInner::Utp(utp_stream) => tokio_io::io::shutdown(utp_stream.into_inner())
                .and_then(|stream| stream.finalize().infallible())
                .into_boxed(),
            #[cfg(test)]
            PaStreamInner::Mem(stream) => tokio_io::io::shutdown(stream.into_inner())
                .map(|_stream| ())
                .into_boxed(),
        }
    }

    pub fn direct_connect(
        handle: &Handle,
        addr: &PaAddr,
        their_pk: PublicEncryptKey,
        config: &ConfigFile,
    ) -> BoxFuture<PaStream, DirectConnectError> {
        let disable_tcp = config.tcp_disabled();

        match *addr {
            PaAddr::Tcp(ref tcp_addr) => {
                if disable_tcp {
                    future::err(DirectConnectError::TcpDisabled).into_boxed()
                } else {
                    TcpStream::connect(tcp_addr, handle)
                        .map_err(DirectConnectError::TcpConnect)
                        .and_then(move |stream| {
                            connect_handshake(stream, &their_pk).map(|(framed, shared_secret)| {
                                PaStream::from_framed_tcp_stream(framed, shared_secret)
                            })
                        }).into_boxed()
                }
            }
            PaAddr::Utp(utp_addr) => {
                let (socket, _listener) = try_bfut!(
                    UtpSocket::bind(&addr!("0.0.0.0:0"), handle)
                        .map_err(DirectConnectError::UtpBind)
                );

                future::lazy(move || {
                    socket
                        .connect(&utp_addr)
                        .map_err(DirectConnectError::UtpConnect)
                        .and_then(move |stream| {
                            connect_handshake(stream, &their_pk).map(|(framed, shared_secret)| {
                                PaStream::from_framed_utp_stream(framed, shared_secret)
                            })
                        })
                }).into_boxed()
            }
        }
    }

    /// Execute both TCP and uTP rendezvous connections.
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

        let (our_pk, our_sk) = gen_encrypt_keypair();
        let pump_channels = {
            let our_pk = our_pk;
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
                            let msg = try_bfut!(
                                serialisation::serialise(&msg)
                                    .map_err(PaRendezvousConnectError::SerializeMsg)
                            );
                            let msg = Bytes::from(msg);
                            channel
                                .send(msg)
                                .map_err(PaRendezvousConnectError::ChannelWrite)
                                .and_then(|channel| {
                                    channel.into_future().map_err(|(err, _channel)| {
                                        PaRendezvousConnectError::ChannelRead(err)
                                    })
                                }).and_then(move |(msg_opt, _channel)| {
                                    if let Some(msg) = msg_opt {
                                        let msg: PaRendezvousMsg = (
                                            serialisation::deserialise(&msg)
                                                .map_err(PaRendezvousConnectError::DeserializeMsg)
                                        )?;
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
                                    }
                                }).into_boxed()
                        })
                })
        };

        let handle = handle.clone();
        let tcp_connect = { TcpStream::rendezvous_connect(tcp_ch_1, &handle, p2p) };
        let udp_connect = {
            UdpSocket::rendezvous_connect(utp_ch_1, &handle, p2p)
                .map_err(UtpRendezvousConnectError::Rendezvous)
                .and_then(move |(udp_socket, addr, _our_pub_addr)| {
                    trace!("udp rendezvous connect succeeded.");
                    let (utp_socket, utp_listener) = {
                        UtpSocket::from_socket(udp_socket, &handle)
                            .map_err(UtpRendezvousConnectError::IntoUtpSocket)?
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
                .and_then(move |((their_pk, tcp_connect), udp_connect)| {
                    let shared_secret = our_sk.shared_secret(&their_pk);
                    let shared_key0 = shared_secret.clone();
                    let tcp_connect = tcp_connect.map(|(stream, _our_pub_addr)| PaStream {
                        inner: PaStreamInner::Tcp(Framed::new(stream)),
                        shared_secret: shared_key0,
                    });
                    if our_pk > their_pk {
                        let utp_connect = {
                            udp_connect.and_then(|(utp_socket, _utp_listener, addr)| {
                                utp_socket
                                    .connect(&addr)
                                    .map_err(UtpRendezvousConnectError::UtpConnect)
                                    .map(|stream| PaStream {
                                        inner: PaStreamInner::Utp(Framed::new(stream)),
                                        shared_secret,
                                    })
                            })
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
                        };
                        connect
                            .and_then(|stream| {
                                stream
                                    .send_serialized(&ChooseMsg)
                                    .map_err(PaRendezvousConnectError::SendChoose)
                            }).into_boxed()
                    } else {
                        let tcp_connect = tcp_connect.map(take_chosen);
                        let utp_connect = {
                            udp_connect
                                .and_then(|(_utp_socket, utp_listener, addr)| {
                                    utp_listener
                                        .incoming()
                                        .filter(move |stream| stream.peer_addr() == addr)
                                        .first_ok()
                                        .map_err(UtpRendezvousConnectError::UtpAccept)
                                        .map(|stream| PaStream {
                                            inner: PaStreamInner::Utp(Framed::new(stream)),
                                            shared_secret,
                                        })
                                }).map(take_chosen)
                        };
                        let connect = {
                            tcp_connect
                                .first_ok2(utp_connect)
                                .map_err(|(tcp_err, utp_err)| {
                                    PaRendezvousConnectError::AllProtocolsFailed {
                                        tcp: Box::new(tcp_err),
                                        utp: Box::new(utp_err),
                                    }
                                }).and_then(|res| res)
                        };

                        connect.into_boxed()
                    }
                })
        };

        ret.into_boxed()
    }

    pub fn send_serialized<T: Serialize>(self, item: T) -> BoxFuture<PaStream, PaStreamWriteError> {
        let serialized =
            try_bfut!(serialisation::serialise(&item).map_err(PaStreamWriteError::Serialize));
        self.send(Bytes::from(serialized)).into_boxed()
    }

    pub fn recv_serialized<T: Serialize + DeserializeOwned + 'static>(
        self,
    ) -> BoxFuture<(Option<T>, PaStream), PaStreamReadError> {
        self.into_future()
            .map_err(|(e, _stream)| e)
            .and_then(|(msg_opt, stream)| match msg_opt {
                None => Ok((None, stream)),
                Some(msg) => {
                    let deserialized = {
                        serialisation::deserialise(&msg).map_err(PaStreamReadError::Deserialise)?
                    };
                    Ok((Some(deserialized), stream))
                }
            }).into_boxed()
    }

    pub fn peer_addr(&self) -> io::Result<PaAddr> {
        match self.inner {
            PaStreamInner::Tcp(ref stream) => Ok(PaAddr::Tcp(stream.get_ref().peer_addr()?)),
            PaStreamInner::Utp(ref stream) => Ok(PaAddr::Utp(stream.get_ref().peer_addr())),
            #[cfg(test)]
            PaStreamInner::Mem(_) => Ok(tcp_addr!("0.0.0.0:0")),
        }
    }

    #[cfg(test)]
    pub fn into_tcp_stream(self) -> TcpStream {
        match self.inner {
            PaStreamInner::Tcp(stream) => stream.into_inner(),
            _ => panic!("not a tcp stream"),
        }
    }

    #[cfg(test)]
    pub fn into_utp_stream(self) -> UtpStream {
        match self.inner {
            PaStreamInner::Utp(stream) => stream.into_inner(),
            _ => panic!("not a utp stream"),
        }
    }
}

fn connect_handshake<S: AsyncRead + AsyncWrite + 'static>(
    stream: S,
    server_pk: &PublicEncryptKey,
) -> BoxFuture<(Framed<S>, SharedSecretKey), DirectConnectError> {
    let (client_pk, client_sk) = gen_encrypt_keypair();
    let req = ListenerMsg {
        client_pk,
        kind: ListenerMsgKind::Connect,
    };
    let msg = try_bfut!(
        server_pk
            .anonymously_encrypt(&req)
            .map_err(DirectConnectError::Encrypt)
    );
    let msg = BytesMut::from(msg);

    let shared_secret = client_sk.shared_secret(server_pk);
    Framed::new(stream)
        .send(msg)
        .map_err(DirectConnectError::Write)
        .map(|framed| (framed, shared_secret))
        .into_boxed()
}

fn take_chosen<Ei: 'static, Eo: 'static>(
    stream: PaStream,
) -> BoxFuture<PaStream, PaRendezvousConnectError<Ei, Eo>> {
    stream
        .recv_serialized()
        .map_err(PaRendezvousConnectError::ReadStream)
        .and_then(|(msg_opt, stream)| {
            let _: ChooseMsg = msg_opt.ok_or(PaRendezvousConnectError::RemoteDisconnected)?;
            Ok(stream)
        }).into_boxed()
}

impl Stream for PaStream {
    type Item = BytesMut;
    type Error = PaStreamReadError;

    fn poll(&mut self) -> Result<Async<Option<BytesMut>>, PaStreamReadError> {
        let msg_opt_async = match self.inner {
            PaStreamInner::Tcp(ref mut framed) => framed.poll().map_err(PaStreamReadError::Read)?,
            PaStreamInner::Utp(ref mut framed) => framed.poll().map_err(PaStreamReadError::Read)?,
            #[cfg(test)]
            PaStreamInner::Mem(ref mut framed) => framed.poll().map_err(PaStreamReadError::Read)?,
        };
        match msg_opt_async {
            Async::Ready(Some(msg)) => {
                let msg = self
                    .shared_secret
                    .decrypt_bytes(&msg)
                    .map_err(PaStreamReadError::Decrypt)?;
                Ok(Async::Ready(Some(BytesMut::from(msg))))
            }
            Async::Ready(None) => Ok(Async::Ready(None)),
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}

impl Sink for PaStream {
    type SinkItem = Bytes;
    type SinkError = PaStreamWriteError;

    fn start_send(&mut self, msg: Bytes) -> Result<AsyncSink<Bytes>, PaStreamWriteError> {
        let encrypted_msg = BytesMut::from(
            self.shared_secret
                .encrypt_bytes(&msg)
                .map_err(PaStreamWriteError::Encrypt)?,
        );

        let res = match self.inner {
            PaStreamInner::Tcp(ref mut framed) => framed
                .start_send(encrypted_msg)
                .map_err(PaStreamWriteError::Write)?,
            PaStreamInner::Utp(ref mut framed) => framed
                .start_send(encrypted_msg)
                .map_err(PaStreamWriteError::Write)?,
            #[cfg(test)]
            PaStreamInner::Mem(ref mut framed) => framed
                .start_send(encrypted_msg)
                .map_err(PaStreamWriteError::Write)?,
        };
        match res {
            AsyncSink::Ready => Ok(AsyncSink::Ready),
            // TODO: optimize this, we could buffer one encrypted msg rather than re-encrypting.
            AsyncSink::NotReady(_encrypted_msg) => Ok(AsyncSink::NotReady(msg)),
        }
    }

    fn poll_complete(&mut self) -> Result<Async<()>, PaStreamWriteError> {
        match self.inner {
            PaStreamInner::Tcp(ref mut framed) => {
                framed.poll_complete().map_err(PaStreamWriteError::Write)
            }
            PaStreamInner::Utp(ref mut framed) => {
                framed.poll_complete().map_err(PaStreamWriteError::Write)
            }
            #[cfg(test)]
            PaStreamInner::Mem(ref mut framed) => {
                framed.poll_complete().map_err(PaStreamWriteError::Write)
            }
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum DirectConnectError {
        TcpDisabled {
            description("tcp is disabled in the config")
        }
        TcpConnect(e: io::Error) {
            description("error connecting to tcp endpoint")
            display("error connecting to tcp endpoint: {}", e)
            cause(e)
        }
        UtpBind(e: io::Error) {
            description("error binding utp socket")
            display("error binding utp socket: {}", e)
            cause(e)
        }
        UtpConnect(e: io::Error) {
            description("error forming utp connection")
            display("error forming utp connection")
            cause(e)
        }
        Write(e: io::Error) {
            description("error writing to connected stream")
            display("error writing to connected stream: {}", e)
            cause(e)
        }
        Encrypt(e: EncryptionError) {
            description("error encrypting connect request")
            display("error encrypting connect request: {}", e)
            cause(e)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum PaStreamReadError {
        Read(e: io::Error) {
            description("error reading on the underlying socket")
            display("error reading on the underlying socket: {}", e)
            cause(e)
        }
        Decrypt(e: EncryptionError) {
            description("error decrypting data received from remote peer")
            display("error decrypting data received from remote peer: {}", e)
            cause(e)
        }
        Deserialise(e: SerialisationError) {
            description("error deserialising data from remote peer")
            display("error deserialising data from remote peer: {}", e)
            cause(e)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum PaStreamWriteError {
        Write(e: io::Error) {
            description("error writing to the underlying socket")
            display("error writing to the underlying socket: {}", e)
            cause(e)
        }
        Encrypt(e: EncryptionError) {
            description("error encrypting message to send to remote peer")
            display("error encrypting message to send to remote peer: {}", e)
            cause(e)
        }
        Serialize(e: SerialisationError) {
            description("error serialising data to send to remote peer")
            display("error serialising data to send to remote peer: {}", e)
            cause(e)
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
            IntoUtpSocket(ref e) | UtpConnect(ref e) => Some(e),
            UtpAccept(ref es) => match es.first() {
                Some(e) => Some(e),
                None => None,
            },
        }
    }
}

#[derive(Debug)]
pub enum PaRendezvousConnectError<Ei, Eo> {
    ChannelWrite(Eo),
    ChannelRead(Ei),
    ChannelClosed,
    SerializeMsg(SerialisationError),
    DeserializeMsg(SerialisationError),
    RemoteDisconnected,
    AllProtocolsFailed {
        tcp: Box<TcpRendezvousConnectError<Void, SendError<Bytes>>>,
        utp: Box<UtpRendezvousConnectError<Void, SendError<Bytes>>>,
    },
    ReadStream(PaStreamReadError),
    ExpectedChoose,
    SendChoose(PaStreamWriteError),
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
            PaRendezvousConnectError::SerializeMsg(ref e) => write!(
                formatter,
                "error serializing message to remote channel: {}",
                e,
            ),
            PaRendezvousConnectError::DeserializeMsg(ref e) => write!(
                formatter,
                "error deserializing message from rendezvous channel: {}",
                e
            ),
            PaRendezvousConnectError::RemoteDisconnected => {
                write!(formatter, "remote peer disconnected",)
            }
            PaRendezvousConnectError::AllProtocolsFailed { ref tcp, ref utp } => write!(
                formatter,
                "all rendezvous connect protocols failed. tcp error: {}; utp error: {}",
                tcp, utp,
            ),
            PaRendezvousConnectError::ReadStream(ref e) => {
                write!(formatter, "error reading from connected stream: {}", e,)
            }
            PaRendezvousConnectError::ExpectedChoose => write!(
                formatter,
                "protocol error - peer did not send choose message.",
            ),
            PaRendezvousConnectError::SendChoose(ref e) => {
                write!(formatter, "failed to write choose message to stream: {}", e,)
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
            PaRendezvousConnectError::SerializeMsg(..) => {
                "error serializing message to remote channel"
            }
            PaRendezvousConnectError::DeserializeMsg(..) => {
                "error deserializing message from rendezvous channel"
            }
            PaRendezvousConnectError::RemoteDisconnected => "remote peer disconnected",
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
            PaRendezvousConnectError::SerializeMsg(ref e) => Some(e),
            PaRendezvousConnectError::DeserializeMsg(ref e) => Some(e),
            PaRendezvousConnectError::ReadStream(ref e) => Some(e),
            PaRendezvousConnectError::SendChoose(ref e) => Some(e),
            PaRendezvousConnectError::AllProtocolsFailed { .. }
            | PaRendezvousConnectError::ExpectedChoose
            | PaRendezvousConnectError::RemoteDisconnected
            | PaRendezvousConnectError::ChannelClosed => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use config::DevConfigSettings;
    use future_utils::bi_channel;
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

    mod framed_pastream {
        use super::*;
        use tokio_io;

        mod tcp {
            use super::*;

            #[test]
            fn it_fails_to_send_packets_bigger_than_the_size_limit() {
                let mut evloop = unwrap!(Core::new());
                let handle = evloop.handle();
                let (listener_pk, listener_sk) = gen_encrypt_keypair();
                let listener = unwrap!(PaListener::bind_reusable(
                    &tcp_addr!("0.0.0.0:0"),
                    &handle,
                    listener_sk,
                    listener_pk,
                ));
                let listener_addr = unwrap!(listener.local_addr()).unspecified_to_localhost();

                let config = unwrap!(ConfigFile::new_temporary());
                let data = vec![1; ::MAX_PAYLOAD_SIZE + 1];
                let send_data =
                    PaStream::direct_connect(&handle, &listener_addr, listener_pk, &config)
                        .map_err(|e| panic!("failed to connect: {}", e))
                        .and_then(move |stream| stream.send(Bytes::from(data)))
                        .and_then(|_stream| Ok(()));

                let task = listener
                    .incoming()
                    .into_future()
                    .map_err(|(e, _incoming)| panic!("Failed to accept connection: {}", e))
                    .map(|(stream_addr_opt, _incoming)| unwrap!(stream_addr_opt))
                    .and_then(|stream| {
                        stream
                            .into_future()
                            .map_err(|(e, _stream)| panic!("Failed to read from client: {}", e))
                            .map(|(_msg_opt, _stream)| ())
                    }).join(send_data);
                let res = evloop.run(task);

                match res {
                    Err(PaStreamWriteError::Write(e)) => match e.kind() {
                        io::ErrorKind::InvalidInput => (),
                        k => panic!("unexpected error kind: {:?}", k),
                    },
                    res => panic!("unexpected result: {:?}", res),
                };
            }

            #[test]
            fn when_client_sends_too_big_packet_it_closes_its_connection() {
                let mut evloop = unwrap!(Core::new());
                let handle = evloop.handle();
                let (listener_pk, listener_sk) = gen_encrypt_keypair();
                let listener = unwrap!(PaListener::bind_reusable(
                    &tcp_addr!("0.0.0.0:0"),
                    &handle,
                    listener_sk,
                    listener_pk,
                ));
                let listener_addr = unwrap!(listener.local_addr()).unspecified_to_localhost();

                let config = unwrap!(ConfigFile::new_temporary());
                let data = vec![1; ::MAX_PAYLOAD_SIZE + 1];
                let send_data = {
                    PaStream::direct_connect(&handle, &listener_addr, listener_pk, &config)
                        .map_err(|e| panic!("error connecting: {}", e))
                        // let's unwrap Framed, so that we could send big packets (evil)
                        .map(|stream| {
                            match stream.inner {
                                PaStreamInner::Tcp(framed) => framed.into_inner(),
                                _ => panic!("we got a utp stream somehow"),
                            }
                        })
                        .and_then(move |stream| tokio_io::io::write_all(stream, data))
                        .map_err(|e| panic!("Failed to send data: {}", e))
                        .map(|_stream| ())
                };

                let task = listener
                    .incoming()
                    .into_future()
                    .map_err(|(e, _incoming)| panic!("Failed to accept connection: {}", e))
                    .map(|(stream_addr_opt, _incoming)| unwrap!(stream_addr_opt))
                    .and_then(|stream| {
                        stream
                            .into_future()
                            .map_err(|(e, _stream)| e)
                            .map(|(_msg_opt, _stream)| ())
                    }).join(send_data);

                let res = evloop.run(task);
                match res {
                    Err(PaStreamReadError::Read(e)) => match e.kind() {
                        io::ErrorKind::InvalidData => (),
                        k => panic!("unexpected error kind: {:?}", k),
                    },
                    res => panic!("unexpected result: {:?}", res),
                };
            }
        }
    }
}
