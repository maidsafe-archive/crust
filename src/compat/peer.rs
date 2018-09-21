use future_utils::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::stream::{SplitSink, SplitStream};
use futures::sync::oneshot;
use priv_prelude::*;

/// The maximum size of packets sent by `CompatPeer` in bytes.
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
    pub enum CompatPeerError {
        /// Peer was destroyed
        Destroyed {
            description("CompatPeer has been destroyed")
        }
        /// Peer error
        Peer(e: PeerError) {
            description("peer error")
            display("peer error: {}", e)
            cause(e)
            from()
        }
        /// Tried to send a message that was too big
        OversizedMessage {
            description("tried to send a message that was too big")
        }
    }
}

/// A `CompatPeer` wraps an underlying transport protocol (eg. TCP).
///
/// An important thing to understand about `CompatPeer`s is that they are *infinitely buffered*. You
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
pub struct CompatPeer {
    inner: Option<Inner>,
}

pub struct Inner {
    stream_rx: Option<SplitStream<Peer>>,
    write_tx: UnboundedSender<TaskMsg>,
    peer_addr: PaAddr,
    kind: CrustUser,
    uid: PublicEncryptKey,
}

enum TaskMsg<T = Peer>
where
    T: Stream<Item = BytesMut>,
    T: Sink<SinkItem = Bytes, SinkError = PeerError>,
{
    Send(Priority, Bytes),
    Shutdown(SplitStream<T>),
    /// Tells `CompatPeerTask` to close it's activity, reunite and return the inner peer.
    GetInnerStream(oneshot::Sender<T>, SplitStream<T>),
}

struct CompatPeerTask<T = Peer>
where
    T: Stream<Item = BytesMut>,
    T: Sink<SinkItem = Bytes, SinkError = PeerError>,
{
    handle: Handle,
    stream_rx: Option<SplitStream<T>>,
    stream_tx: Option<SplitSink<T>>,
    write_queue: BTreeMap<Priority, VecDeque<(Instant, Bytes)>>,
    write_rx: UnboundedReceiver<TaskMsg<T>>,
}

impl CompatPeer {
    /// Get the kind of peer
    pub fn kind(&self) -> CrustUser {
        unwrap!(self.inner.as_ref()).kind
    }

    /// Get the peer's uid
    pub fn public_id(&self) -> PublicEncryptKey {
        unwrap!(self.inner.as_ref()).uid
    }

    /// Wraps a `Peer` and turns it into a `CompatPeer`.
    pub fn wrap_peer(
        handle: &Handle,
        peer: Peer,
        uid: PublicEncryptKey,
        peer_addr: PaAddr,
    ) -> CompatPeer {
        let kind = peer.kind();
        let (stream_tx, stream_rx) = peer.split();
        let (write_tx, write_rx) = mpsc::unbounded();
        let task = CompatPeerTask::new(handle, stream_tx, write_rx);
        handle.spawn({
            task.map_err(|e| {
                error!("CompatPeer task failed!: {}", e);
            })
        });
        let inner = Inner {
            stream_rx: Some(stream_rx),
            write_tx,
            peer_addr,
            kind,
            uid,
        };
        CompatPeer { inner: Some(inner) }
    }

    /// Get the address of the remote peer (if the socket is still active).
    pub fn peer_addr(&self) -> Result<PaAddr, CompatPeerError> {
        match self.inner {
            Some(ref inner) => Ok(inner.peer_addr),
            None => Err(CompatPeerError::Destroyed),
        }
    }

    /// Returns an inner peer that is wrapped by this `CompatPeer`.
    /// This method is only meant to be used in tests.
    /// Note, that socket write buffer will be destroyed.
    pub fn into_inner(mut self) -> BoxFuture<Peer, CompatPeerError> {
        let mut inner = try_bfut!(self.inner.take().ok_or(CompatPeerError::Destroyed));
        let stream_rx = unwrap!(inner.stream_rx.take());
        let (inner_stream_tx, inner_stream_rx) = oneshot::channel();
        let _ = inner
            .write_tx
            .unbounded_send(TaskMsg::GetInnerStream(inner_stream_tx, stream_rx));
        inner_stream_rx
            .map_err(|_e| CompatPeerError::Destroyed)
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

impl Stream for CompatPeer {
    type Item = BytesMut;
    type Error = CompatPeerError;

    fn poll(&mut self) -> Result<Async<Option<BytesMut>>, CompatPeerError> {
        let mut inner = match self.inner.take() {
            Some(inner) => inner,
            None => return Err(CompatPeerError::Destroyed),
        };
        let ret = Ok(unwrap!(inner.stream_rx.as_mut()).poll()?);
        self.inner = Some(inner);
        ret
    }
}

impl Sink for CompatPeer {
    type SinkItem = (Priority, Bytes);
    type SinkError = CompatPeerError;

    fn start_send(
        &mut self,
        (priority, msg): (Priority, Bytes),
    ) -> Result<AsyncSink<(Priority, Bytes)>, CompatPeerError> {
        if msg.len() > MAX_PAYLOAD_SIZE {
            return Err(CompatPeerError::OversizedMessage);
        }
        let inner = match self.inner {
            Some(ref mut inner) => inner,
            None => return Err(CompatPeerError::Destroyed),
        };
        let _ = inner.write_tx.unbounded_send(TaskMsg::Send(priority, msg));
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, CompatPeerError> {
        Ok(Async::Ready(()))
    }
}

impl<T> CompatPeerTask<T>
where
    T: Stream<Item = BytesMut>,
    T: Sink<SinkItem = Bytes, SinkError = PeerError>,
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

impl Future for CompatPeerTask<Peer> {
    type Item = ();
    type Error = CompatPeerError;

    fn poll(&mut self) -> Result<Async<()>, CompatPeerError> {
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
            }).map(|(&priority, _)| priority)
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
                    let peer = unwrap!(stream_rx.reunite(stream_tx));
                    let soft_timeout = Timeout::new(Duration::from_secs(1), &self.handle);
                    let hard_timeout = Timeout::new(Duration::from_secs(10), &self.handle);
                    self.handle.spawn({
                        peer.finalize()
                            .log_error(LogLevel::Warn, "shutdown socket")
                            .join(soft_timeout)
                            .map(|((), ())| ())
                            .until(hard_timeout)
                            .map(|opt| {
                                opt.unwrap_or_else(|| warn!("timed out shutting down socket"))
                            }).infallible()
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
    use net::peer;
    use tokio_core::reactor::Core;
    use util;

    mod compat_peer {
        use super::*;
        use rand::{self, Rng};

        fn random_msgs(num_msgs: usize) -> Vec<Bytes> {
            let mut msgs = Vec::with_capacity(num_msgs);
            for _ in 0..num_msgs {
                let size = rand::thread_rng().gen_range(0, 10_000);
                let data = util::random_vec(size);
                let msg = Bytes::from(data);
                msgs.push(msg);
            }
            msgs
        }

        fn exchange_messages(bind_addr: PaAddr) {
            let mut core = unwrap!(Core::new());
            let handle = core.handle();
            let config = unwrap!(ConfigFile::new_temporary());
            let (listener_pk, listener_sk) = gen_encrypt_keypair();
            let (client_pk, _client_sk) = gen_encrypt_keypair();

            let listener = unwrap!(PaListener::bind(
                &bind_addr,
                &handle,
                listener_sk,
                listener_pk,
            ));
            let addr = unwrap!(listener.local_addr()).unspecified_to_localhost();

            let num_msgs = 1000;
            let msgs = random_msgs(num_msgs);

            let f0 = {
                let msgs: Vec<(Priority, _)> = msgs.iter().cloned().map(|m| (1, m)).collect();
                let handle = handle.clone();
                PaStream::direct_connect(&handle, &addr, listener_pk, &config)
                    .map_err(|e| panic!("error connecting: {}", e))
                    .and_then(move |stream| {
                        let their_uid = listener_pk;
                        let peer = peer::from_handshaken_stream(
                            &handle,
                            their_uid,
                            stream,
                            CrustUser::Node,
                        );
                        let socket = CompatPeer::wrap_peer(&handle, peer, their_uid, addr);
                        socket
                            .send_all(stream::iter_ok::<_, CompatPeerError>(msgs))
                            .map_err(|e| panic!("error sending: {}", e))
                            .map(|(_socket, _msgs)| ())
                    })
            };

            let f1 = {
                let handle = handle.clone();
                listener
                    .incoming()
                    .into_future()
                    .map_err(|(err, _)| panic!("incoming error: {}", err))
                    .and_then(move |(stream_opt, _)| {
                        let stream = unwrap!(stream_opt);
                        let peer = peer::from_handshaken_stream(
                            &handle,
                            client_pk,
                            stream,
                            CrustUser::Node,
                        );
                        let socket = CompatPeer::wrap_peer(&handle, peer, client_pk, addr);
                        socket
                            .take(num_msgs as u64)
                            .map_err(|e| panic!("error reading: {}", e))
                            .collect()
                            .map(move |msgs_recv| {
                                for i in 0..msgs.len() {
                                    if msgs[i] != unwrap!(msgs_recv.get(i), "msg {} missing", i) {
                                        panic!(
                                            "error in msg[{}]\n{:?} != {:?}",
                                            i, msgs_recv[i], msgs[i]
                                        );
                                    }
                                }
                                assert_eq!(msgs_recv, msgs);
                            })
                    })
            };

            core.run(f0.join(f1).map(|((), ())| ())).void_unwrap()
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

    mod compat_peer_task {
        use super::*;

        mod poll_task {
            use super::*;
            use config::ConfigFile;

            #[test]
            fn when_task_is_get_inner_stream_it_returns_true() {
                let mut evloop = unwrap!(Core::new());
                let handle = evloop.handle();

                let config = unwrap!(ConfigFile::new_temporary());
                let (listener_pk, listener_sk) = gen_encrypt_keypair();
                let addr = PaAddr::Tcp(addr!("0.0.0.0:0"));
                let listener = unwrap!(PaListener::bind(&addr, &handle, listener_sk, listener_pk,));
                let stream = unwrap!(evloop.run(PaStream::direct_connect(
                    &handle,
                    &unwrap!(listener.local_addr()).unspecified_to_localhost(),
                    listener_pk,
                    &config
                )));

                let stream = stream
                    .sink_map_err(|e| panic!("oh damn: {}", e))
                    .map_err(|e| panic!("oh no: {}", e));
                let (stream_tx, stream_rx) = stream.split();
                let (task_tx, task_rx) = mpsc::unbounded();
                let mut task = CompatPeerTask::new(&handle, stream_tx, task_rx);

                let (inner_stream_tx, _inner_stream_rx) = oneshot::channel();
                let send_task = task_tx.send(TaskMsg::GetInnerStream(inner_stream_tx, stream_rx));
                let _ = unwrap!(evloop.run(send_task));

                let close_socket_task = task.poll_task();

                assert!(close_socket_task);
            }
        }
    }
}
