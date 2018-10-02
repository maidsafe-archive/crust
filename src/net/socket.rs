// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use bytes::BytesMut;
use futures::stream::{SplitSink, SplitStream};
use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::sync::oneshot;
use log::LogLevel;
use priv_prelude::*;
use tokio_io;

/// The maximum size of packets sent by `Socket` in bytes.
pub const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;

/// Message priority. Messages with lower number (higher priority) will be sent first.
/// Priority `0` is reserved for internal messages. Use `priority = 1` and upwards.
pub type Priority = u8;

/// Minimum priority for droppable messages. Messages with lower values will never be dropped.
pub const MSG_DROP_PRIORITY: u8 = 2;
/// Maximum age of a message waiting to be sent. If a message is older, the queue is dropped.
const MAX_MSG_AGE_SECS: u64 = 60;

quick_error! {
    /// Errors that can occur on sockets.
    #[derive(Debug)]
    pub enum SocketError {
        Destroyed {
            description("Socket has been destroyed")
        }
        Io(e: io::Error) {
            description("Io error on socket")
            display("Io error on socket: {}", e)
            cause(e)
            from()
        }
        Encrypt(e: EncryptError) {
            description("Error encrypting message")
            display("Error encrypting message: {}", e)
            cause(e)
        }
        Decrypt(e: DecryptError) {
            description("Error decrypting message")
            display("Error decrypting message: {}", e)
            cause(e)
        }
    }
}

/// A `Socket` wraps an underlying transport protocol (eg. TCP) and acts a `Sink`/`Stream` for
/// sending/receiving messages of type `M`.
///
/// An important thing to understand about `Socket`s is that they are *infinitely buffered*. You
/// can just keep pumping more and more data into them without blocking the writing task even if
/// the underlying transport can't keep up. Eventually, once the latency builds up too much (ie.
/// the messages it's writing are more than `MAX_MSG_AGE_SECS` old) then it will drop its entire
/// outgoing buffer. This may sound broken in several ways, but it's behaviour that MaidSafe's
/// routing layer currently expects.
///
/// Another thing is that messages can be sent with a `Priority`. Higher (lower-numbered)
/// priorities will always be sent first. Highest-priority messages, those with priority below
/// `MSG_DROP_PRIORITY`, will never be dropped no matter how much the latency on the socket builds
/// up or how large the buffer grows 😬
pub struct Socket<M> {
    inner: Option<Inner>,
    _ph: PhantomData<M>,
}

pub struct Inner {
    stream_rx: Option<SplitStream<FramedPaStream>>,
    write_tx: UnboundedSender<TaskMsg>,
    peer_addr: PaAddr,
    crypto_ctx: CryptoContext,
}

enum TaskMsg<T = FramedPaStream>
where
    T: Stream<Item = BytesMut>,
    T: Sink<SinkItem = BytesMut, SinkError = io::Error>,
{
    Send(Priority, BytesMut),
    Shutdown(SplitStream<T>),
    /// Tells `SocketTask` to close it's activity, reunite and return the inner stream.
    GetInnerStream(oneshot::Sender<T>, SplitStream<T>),
}

struct SocketTask<T = FramedPaStream>
where
    T: Stream<Item = BytesMut>,
    T: Sink<SinkItem = BytesMut, SinkError = io::Error>,
{
    handle: Handle,
    stream_rx: Option<SplitStream<T>>,
    stream_tx: Option<SplitSink<T>>,
    write_queue: BTreeMap<Priority, VecDeque<(Instant, BytesMut)>>,
    write_rx: UnboundedReceiver<TaskMsg<T>>,
}

impl<M: 'static> Socket<M> {
    /// Wraps a `PaStream` and turns it into a `Socket`.
    pub fn wrap_pa(
        handle: &Handle,
        stream: FramedPaStream,
        peer_addr: PaAddr,
        crypto_ctx: CryptoContext,
    ) -> Socket<M> {
        let (stream_tx, stream_rx) = stream.split();
        let (write_tx, write_rx) = mpsc::unbounded();
        let task = SocketTask::new(handle, stream_tx, write_rx);
        handle.spawn({
            task.map_err(|e| {
                error!("Socket task failed!: {}", e);
            })
        });
        let inner = Inner {
            stream_rx: Some(stream_rx),
            write_tx,
            peer_addr,
            crypto_ctx,
        };
        Socket {
            inner: Some(inner),
            _ph: PhantomData,
        }
    }

    /// Replace crypto context used to encrypt/decrypt data.
    /// This is useful, for example, when we want to switch from anonymous encryption to
    /// authenticated one.
    pub fn use_crypto_ctx(&mut self, crypto_ctx: CryptoContext) {
        if let Some(ref mut inner) = self.inner {
            inner.crypto_ctx = crypto_ctx;
        }
    }

    /// Get the address of the remote peer (if the socket is still active).
    pub fn peer_addr(&self) -> Result<PaAddr, SocketError> {
        match self.inner {
            Some(ref inner) => Ok(inner.peer_addr),
            None => Err(SocketError::Destroyed),
        }
    }

    /// Consume this socket and return it as a socket with a different messages type. Any messages
    /// of the old type that are in the outgoing buffer will still be sent.
    pub fn change_message_type<N>(self) -> Socket<N> {
        Socket {
            inner: self.inner,
            _ph: PhantomData,
        }
    }

    /// Returns an inner stream that is wrapped by this `Socket`.
    /// This method is only meant to be used in tests.
    /// Note, that socket write buffer will be destroyed.
    pub fn into_inner(mut self) -> BoxFuture<FramedPaStream, SocketError> {
        let mut inner = try_bfut!(self.inner.take().ok_or(SocketError::Destroyed));
        let stream_rx = unwrap!(inner.stream_rx.take());
        let (inner_stream_tx, inner_stream_rx) = oneshot::channel();
        let _ = inner
            .write_tx
            .unbounded_send(TaskMsg::GetInnerStream(inner_stream_tx, stream_rx));
        inner_stream_rx
            .map_err(|_e| SocketError::Destroyed)
            .into_boxed()
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(stream_rx) = self.stream_rx.take() {
            let _ = self.write_tx.unbounded_send(TaskMsg::Shutdown(stream_rx));
        }
    }
}

impl<M> Stream for Socket<M>
where
    M: Serialize + DeserializeOwned,
{
    type Item = M;
    type Error = SocketError;

    fn poll(&mut self) -> Result<Async<Option<M>>, SocketError> {
        let mut inner = match self.inner.take() {
            Some(inner) => inner,
            None => return Err(SocketError::Destroyed),
        };
        let ret = if let Async::Ready(data_opt) = unwrap!(inner.stream_rx.as_mut()).poll()? {
            let data = match data_opt {
                Some(data) => data,
                None => return Ok(Async::Ready(None)),
            };
            let msg = inner
                .crypto_ctx
                .decrypt(&data)
                .map_err(SocketError::Decrypt)?;
            Ok(Async::Ready(Some(msg)))
        } else {
            Ok(Async::NotReady)
        };
        self.inner = Some(inner);
        ret
    }
}

impl<M> Sink for Socket<M>
where
    M: Serialize + DeserializeOwned,
{
    type SinkItem = (Priority, M);
    type SinkError = SocketError;

    fn start_send(
        &mut self,
        (priority, msg): (Priority, M),
    ) -> Result<AsyncSink<(Priority, M)>, SocketError> {
        let inner = match self.inner {
            Some(ref mut inner) => inner,
            None => return Err(SocketError::Destroyed),
        };

        let data = inner
            .crypto_ctx
            .encrypt(&msg)
            .map_err(SocketError::Encrypt)?;
        let _ = inner.write_tx.unbounded_send(TaskMsg::Send(priority, data));
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, SocketError> {
        Ok(Async::Ready(()))
    }
}

impl<T> SocketTask<T>
where
    T: Stream<Item = BytesMut>,
    T: Sink<SinkItem = BytesMut, SinkError = io::Error>,
{
    fn new(
        handle: &Handle,
        stream_tx: SplitSink<T>,
        task_rx: UnboundedReceiver<TaskMsg<T>>,
    ) -> Self {
        Self {
            handle: handle.clone(),
            stream_tx: Some(stream_tx),
            stream_rx: None,
            write_queue: BTreeMap::new(),
            write_rx: task_rx,
        }
    }

    /// Check if there's anything to send. If there is, enqueue the messages.
    /// Returns true, when socket task should be terminated, false otherwise.
    fn poll_task(&mut self) -> bool {
        let now = Instant::now();
        loop {
            match unwrap!(self.write_rx.poll()) {
                Async::Ready(Some(TaskMsg::Send(priority, data))) => {
                    let queue = self
                        .write_queue
                        .entry(priority)
                        .or_insert_with(VecDeque::new);
                    queue.push_back((now, data));
                }
                Async::Ready(Some(TaskMsg::Shutdown(stream_rx))) => {
                    self.stream_rx = Some(stream_rx);
                    break;
                }
                Async::Ready(Some(TaskMsg::GetInnerStream(send_me_stream, stream_rx))) => {
                    let stream_tx = unwrap!(self.stream_tx.take());
                    let inner_stream = unwrap!(stream_rx.reunite(stream_tx));
                    let _ = send_me_stream.send(inner_stream);
                    return true;
                }
                Async::Ready(None) | Async::NotReady => break,
            }
        }
        false
    }
}

impl Future for SocketTask<FramedPaStream> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<()>> {
        let close_socket_task = self.poll_task();
        if close_socket_task {
            return Ok(Async::Ready(()));
        }

        let expired_keys: Vec<u8> = self
            .write_queue
            .iter()
            .skip_while(|&(&priority, queue)| {
                priority < MSG_DROP_PRIORITY || // Don't drop high-priority messages.
                queue.front().map_or(true, |&(ref timestamp, _)| {
                    timestamp.elapsed().as_secs() <= MAX_MSG_AGE_SECS
                })
            })
            .map(|(&priority, _)| priority)
            .collect();
        let dropped_msgs: usize = expired_keys
            .iter()
            .filter_map(|priority| self.write_queue.remove(priority))
            .map(|queue| queue.len())
            .sum();
        if dropped_msgs > 0 {
            trace!(
                "Insufficient bandwidth. Dropping {} messages with priority >= {}.",
                dropped_msgs,
                expired_keys[0]
            );
        }

        let mut all_messages_sent = true;
        'outer: for queue in self.write_queue.values_mut() {
            while let Some((time, msg)) = queue.pop_front() {
                match unwrap!(self.stream_tx.as_mut()).start_send(msg)? {
                    AsyncSink::Ready => (),
                    AsyncSink::NotReady(msg) => {
                        queue.push_front((time, msg));
                        all_messages_sent = false;
                        break 'outer;
                    }
                }
            }
        }

        if let Async::Ready(()) = unwrap!(self.stream_tx.as_mut()).poll_complete()? {
            if all_messages_sent {
                if let Some(stream_rx) = self.stream_rx.take() {
                    let stream_tx = unwrap!(self.stream_tx.take());
                    let tcp_stream = unwrap!(stream_rx.reunite(stream_tx)).into_inner();
                    let soft_timeout = Timeout::new(Duration::from_secs(1), &self.handle);
                    let hard_timeout = Timeout::new(Duration::from_secs(10), &self.handle);
                    self.handle.spawn({
                        tokio_io::io::shutdown(tcp_stream)
                            .map(|_stream| ())
                            .log_error(LogLevel::Warn, "shutdown socket")
                            .join(soft_timeout)
                            .map(|((), ())| ())
                            .until(hard_timeout)
                            .map(|opt| {
                                opt.unwrap_or_else(|| warn!("timed out shutting down socket"))
                            })
                            .infallible()
                    });
                    return Ok(Async::Ready(()));
                }
            }
        }

        Ok(Async::NotReady)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rust_sodium::crypto::box_::gen_keypair;
    use tokio_core::reactor::Core;
    use util;

    mod socket {
        use super::*;
        use rand::{self, Rng};

        fn random_msgs(num_msgs: usize) -> Vec<Vec<u8>> {
            let mut msgs = Vec::with_capacity(num_msgs);
            for _ in 0..num_msgs {
                let size = rand::thread_rng().gen_range(0, 10_000);
                let data = util::random_vec(size);
                let msg = data;
                msgs.push(msg);
            }
            msgs
        }

        fn exchange_messages(bind_addr: PaAddr) {
            let mut core = unwrap!(Core::new());
            let handle = core.handle();
            let config = unwrap!(ConfigFile::new_temporary());
            let (listener_pk, listener_sk) = gen_keypair();
            let anon_decrypt_ctx =
                CryptoContext::anonymous_decrypt(listener_pk, listener_sk.clone());

            let listener = unwrap!(PaListener::bind(
                &bind_addr,
                &handle,
                anon_decrypt_ctx.clone(),
                listener_sk,
            ));
            let addr = unwrap!(listener.local_addr()).unspecified_to_localhost();

            let num_msgs = 1000;
            let msgs = random_msgs(num_msgs);

            let f0 = {
                let msgs: Vec<(Priority, _)> = msgs.iter().cloned().map(|m| (1, m)).collect();
                let handle = handle.clone();
                PaStream::direct_connect(&handle, &addr, listener_pk, &config)
                    .map_err(SocketError::from)
                    .and_then(move |(stream, _peer_addr)| {
                        let socket = Socket::<Vec<u8>>::wrap_pa(
                            &handle,
                            stream,
                            addr,
                            CryptoContext::null(),
                        );
                        socket
                            .send_all(stream::iter_ok::<_, SocketError>(msgs))
                            .map(|(_, _)| ())
                    })
            };

            let f1 = {
                let handle = handle.clone();
                listener
                    .incoming()
                    .into_future()
                    .map_err(|(err, _)| panic!("incoming error: {}", err))
                    .and_then(move |(stream_opt, _)| {
                        let (stream, addr) = unwrap!(stream_opt);
                        let socket = Socket::<Vec<u8>>::wrap_pa(
                            &handle,
                            stream,
                            addr,
                            CryptoContext::null(),
                        );
                        socket
                            .take(num_msgs as u64)
                            .collect()
                            .map(move |msgs_recv| {
                                assert_eq!(msgs_recv, msgs);
                            })
                    })
            };

            let _ = unwrap!(core.run(f0.join(f1)));
        }

        #[test]
        fn it_exchanges_messages_via_tcp() {
            exchange_messages(tcp_addr!("0.0.0.0:0"));
        }

        #[test]
        fn it_exchanges_messages_via_utp() {
            exchange_messages(utp_addr!("0.0.0.0:0"));
        }
    }

    mod socket_task {
        use super::*;
        use future_utils::bi_channel;

        mod poll_task {
            use super::*;

            #[test]
            fn when_task_is_get_inner_stream_it_returns_true() {
                let mut evloop = unwrap!(Core::new());
                let handle = evloop.handle();

                let (channel, _other_channel) = bi_channel::unbounded();
                let channel = channel
                    .sink_map_err(|_e| io::Error::new(io::ErrorKind::Other, "sink.send() failed"));
                let (stream_tx, stream_rx) = channel.split();
                let (task_tx, task_rx) = mpsc::unbounded();
                let mut task = SocketTask::new(&handle, stream_tx, task_rx);

                let (inner_stream_tx, _inner_stream_rx) = oneshot::channel();
                let send_task = task_tx.send(TaskMsg::GetInnerStream(inner_stream_tx, stream_rx));
                let _ = unwrap!(evloop.run(send_task));

                let close_socket_task = task.poll_task();

                assert!(close_socket_task);
            }
        }
    }
}
