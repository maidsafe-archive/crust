// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! When Crust attempts to connect with some peer, it tries multiple connections in parallel.
//! Eventually it chooses the first successful one. This module deals with the mechanics of
//! connection choosing.

use self::ConnectError;
use super::handshake_message::HandshakeMessage;
use net::peer;
use priv_prelude::*;

/// When "choose connection" message is received, this data is given.
type ChooseConnectionResult = Option<(HandshakeMessage, PaStream, PublicEncryptKey)>;

/// Future that ensures that both peers select the same connection.
/// Takes all pending handshaken connections and chooses the first one successful.
/// Depending on service id either initiates connection choice message or waits for one.
pub struct ChooseOneConnection<S>
where
    S: Stream<Item = (PaStream, PublicEncryptKey), Error = SingleConnectionError> + 'static,
{
    handle: Handle,
    all_connections: Option<S>,
    all_connections_are_done: bool,
    our_uid: PublicEncryptKey,
    choose_sent: Option<BoxFuture<(PaStream, PublicEncryptKey), SingleConnectionError>>,
    choose_waiting: Vec<BoxFuture<ChooseConnectionResult, SingleConnectionError>>,
    errors: Vec<SingleConnectionError>,
}

impl<S> ChooseOneConnection<S>
where
    S: Stream<Item = (PaStream, PublicEncryptKey), Error = SingleConnectionError> + 'static,
{
    pub fn new(handle: &Handle, connections: S, our_uid: PublicEncryptKey) -> Self {
        Self {
            handle: handle.clone(),
            all_connections: Some(connections),
            all_connections_are_done: false,
            our_uid,
            choose_sent: None,
            choose_waiting: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Polls all potentially ready connections.
    /// Collects all the errors. If none of connections is ready, returns.
    fn poll_connections(&mut self) -> Result<(), SerialisationError> {
        let mut all_conns = unwrap!(
            self.all_connections.take(),
            "ChooseOneConnection was destroyed",
        );
        while !self.all_connections_are_done {
            match all_conns.poll() {
                Ok(Async::Ready(Some((stream, their_uid)))) => {
                    self.on_conn_ready(stream, their_uid)?
                }
                Ok(Async::Ready(None)) => {
                    self.all_connections_are_done = true;
                    break;
                }
                Ok(Async::NotReady) => break,
                Err(e) => self.errors.push(e),
            }
        }
        // Fighting borrow checker
        self.all_connections = Some(all_conns);
        Ok(())
    }

    fn on_conn_ready(
        &mut self,
        stream: PaStream,
        their_uid: PublicEncryptKey,
    ) -> Result<(), SerialisationError> {
        if self.our_uid > their_uid {
            self.choose_sent = Some({
                let msg = Bytes::from(serialisation::serialise(
                    &HandshakeMessage::ChooseConnection,
                )?);
                stream
                    .send(msg)
                    .map_err(SingleConnectionError::Write)
                    .map(move |stream| (stream, their_uid))
                    .into_boxed()
            });
            // we'll take first ready connection
            self.all_connections_are_done = true;
        } else {
            self.choose_waiting.push(
                stream
                    .into_future()
                    .map_err(|(err, _socket)| SingleConnectionError::Read(err))
                    .and_then(move |(msg_opt, stream)| match msg_opt {
                        Some(msg) => {
                            let handshake = {
                                serialisation::deserialise(&msg)
                                    .map_err(SingleConnectionError::Deserialise)?
                            };
                            Ok(Some((handshake, stream, their_uid)))
                        }
                        None => Ok(None),
                    }).into_boxed(),
            );
        }
        Ok(())
    }

    fn send_choose(&mut self) -> Result<Option<Peer>, SingleConnectionError> {
        let handle = &self.handle;
        if let Some(mut fut) = self.choose_sent.take() {
            match fut.poll() {
                Ok(Async::Ready((stream, their_uid))) => {
                    return Ok(Some(peer::from_handshaken_stream(
                        handle,
                        their_uid,
                        stream,
                        CrustUser::Node,
                    )));
                }
                Ok(Async::NotReady) => self.choose_sent = Some(fut),
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// Wait for the first connection that receives "Choose Connection" message.
    fn recv_choose(&mut self) -> Option<Peer> {
        let handle = &self.handle;
        let mut i = 0;
        while i < self.choose_waiting.len() {
            match self.choose_waiting[i].poll() {
                Ok(Async::Ready(Some((HandshakeMessage::ChooseConnection, stream, their_uid)))) => {
                    let _ = self.choose_waiting.swap_remove(i);
                    return Some(peer::from_handshaken_stream(
                        handle,
                        their_uid,
                        stream,
                        CrustUser::Node,
                    ));
                }
                Ok(Async::Ready(Some((_msg, _stream, _their_uid)))) => {
                    self.errors.push(SingleConnectionError::UnexpectedMessage);
                    let _ = self.choose_waiting.swap_remove(i);
                }
                Ok(Async::Ready(None)) => {
                    self.errors.push(SingleConnectionError::ConnectionDropped);
                    let _ = self.choose_waiting.swap_remove(i);
                }
                Ok(Async::NotReady) => i += 1,
                Err(e) => {
                    self.errors.push(e);
                    let _ = self.choose_waiting.swap_remove(i);
                }
            }
        }
        None
    }

    /// Collects all connections that did not finish connection procedure yet.
    fn other_connections(&mut self) -> BoxStream<PaStream, SingleConnectionError> {
        let conns = mem::replace(&mut self.choose_waiting, Vec::new());
        let choose_waiting_conns = {
            stream::iter_ok::<_, SingleConnectionError>(
                conns.into_iter().map(|conn_fut| conn_fut.into_stream()),
            ).flatten()
            .filter_map(|conn_res_opt| conn_res_opt.map(|(_handshake_msg, stream, _uid)| stream))
        };
        let remaining_conns = unwrap!(self.all_connections.take())
            .map(|(stream, _uid)| stream)
            .chain(choose_waiting_conns);

        if let Some(conn_fut) = self.choose_sent.take() {
            remaining_conns
                .chain(conn_fut.map(|(stream, _uid)| stream).into_stream())
                .into_boxed()
        } else {
            remaining_conns.into_boxed()
        }
    }
}

impl<S> Future for ChooseOneConnection<S>
where
    S: Stream<Item = (PaStream, PublicEncryptKey), Error = SingleConnectionError> + 'static,
{
    type Item = (Peer, BoxStream<PaStream, SingleConnectionError>);
    type Error = ConnectError;

    /// Yields first successful connection.
    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        self.poll_connections()?;

        match self.send_choose() {
            Ok(Some(peer)) => return Ok(Async::Ready((peer, self.other_connections()))),
            Err(e) => return Err(ConnectError::AllConnectionsFailed(vec![e])),
            Ok(None) => (),
        }
        if let Some(peer) = self.recv_choose() {
            return Ok(Async::Ready((peer, self.other_connections())));
        }

        if self.all_connections_are_done
            && self.choose_sent.is_none()
            && self.choose_waiting.is_empty()
        {
            let errors = mem::replace(&mut self.errors, Vec::new());
            Err(ConnectError::AllConnectionsFailed(errors))
        } else {
            Ok(Async::NotReady)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub use tokio_core::reactor::Core;

    mod choose_one_connection {
        use super::*;

        fn rand_peer_uid() -> PublicEncryptKey {
            let (pk, _) = gen_encrypt_keypair();
            pk
        }

        /// Constructs fake connection based on in-memory stream.
        fn fake_connection() -> (PaStream, PublicEncryptKey) {
            let (_, our_sk) = gen_encrypt_keypair();
            let shared_secret = our_sk.shared_secret(&rand_peer_uid());
            let mem_stream = Framed::new(memstream::EchoStream::default());
            (
                PaStream::from_framed_mem_stream(mem_stream, shared_secret),
                rand_peer_uid(),
            )
        }

        mod other_connections {
            use super::*;

            #[test]
            fn it_returns_stream_of_all_pending_connections() {
                let mut evloop = unwrap!(Core::new());
                let handle = evloop.handle();

                let conns = stream::iter_ok(vec![fake_connection()]);
                let our_uid = rand_peer_uid();

                let mut choose_conn = ChooseOneConnection::new(&handle, conns, our_uid);
                choose_conn.choose_sent = Some(future::ok(fake_connection()).into_boxed());
                let conn = fake_connection();
                let choose_waiting_conn = (HandshakeMessage::ChooseConnection, conn.0, conn.1);
                choose_conn.choose_waiting =
                    vec![future::ok(Some(choose_waiting_conn)).into_boxed()];

                let other_conns = unwrap!(evloop.run(choose_conn.other_connections().collect()));

                assert_eq!(other_conns.len(), 3);
            }

            #[test]
            fn it_clears_pending_connections() {
                let mut evloop = unwrap!(Core::new());
                let handle = evloop.handle();

                let conns = stream::iter_ok(vec![fake_connection()]);
                let our_uid = rand_peer_uid();

                let mut choose_conn = ChooseOneConnection::new(&handle, conns, our_uid);
                choose_conn.choose_sent = Some(future::ok(fake_connection()).into_boxed());
                let conn = fake_connection();
                let choose_waiting_conn = (HandshakeMessage::ChooseConnection, conn.0, conn.1);
                choose_conn.choose_waiting =
                    vec![future::ok(Some(choose_waiting_conn)).into_boxed()];

                let _ = unwrap!(evloop.run(choose_conn.other_connections().collect()));

                assert!(choose_conn.all_connections.is_none());
                assert!(choose_conn.choose_waiting.is_empty());
                assert!(choose_conn.choose_sent.is_none());
            }
        }

        mod recv_choose {
            use super::*;

            #[test]
            fn it_removes_first_connection_that_receives_choose_message_from_the_waiting_list() {
                let evloop = unwrap!(Core::new());
                let handle = evloop.handle();

                let conns = stream::empty();
                let our_uid = rand_peer_uid();
                let mut choose_conn = ChooseOneConnection::new(&handle, conns, our_uid);
                let conn = fake_connection();
                let choose_waiting_conn = (HandshakeMessage::ChooseConnection, conn.0, conn.1);
                choose_conn.choose_waiting =
                    vec![future::ok(Some(choose_waiting_conn)).into_boxed()];

                let _ = choose_conn.recv_choose();

                assert!(choose_conn.choose_waiting.is_empty());
            }
        }
    }
}
