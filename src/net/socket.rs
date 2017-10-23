use std::net::Shutdown;
use tokio_io::codec::length_delimited::{self, Framed};
use futures::stream::{SplitStream, SplitSink};
use futures::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use bytes::BytesMut;
use maidsafe_utilities::serialisation::{serialise_into, deserialise, SerialisationError};
use priv_prelude::*;

pub const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;
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
        Deserialisation(e: SerialisationError) {
            description("Error deserialising message from socket")
            display("Error deserialising message from socket")
            cause(e)
            from()
        }
    }
}

/// A `Socket` wraps an underlying transport protocol (eg. TCP) and acts a `Sink`/`Stream` for
/// sending/receiving messages of type `M`.
///
/// An important thing to understand about `Socket`s is that they are *infinitely buffered*. You
/// can just keep pumping more and more data into them without blocking the writing task even if
/// the underlying transport can't keep up. Eventually, once the latency builds up too much (ie.
/// the messages it's writing are more than MAX_MSG_AGE_SECS old) then it will drop its entire
/// outgoing buffer. This may sound broken in several ways, but it's behaviour that MaidSafe's
/// routing layer currently expects.
///
/// Another thing is that messages can be sent with a `Priority`. Higher (lower-numbered)
/// priorities will always be sent first. Highest-priority messages, those with priority below
/// MSG_DROP_PRIORITY, will never be dropped no matter how much the latency on the socket builds up
/// or how large the buffer grows 😬
pub struct Socket<M> {
    inner: Option<Inner>,
    _ph: PhantomData<M>,
}

pub struct Inner {
    stream_rx: Option<SplitStream<Framed<TcpStream>>>,
    write_tx: UnboundedSender<TaskMsg>,
    peer_addr: SocketAddr,
}

enum TaskMsg {
    Send(Priority, BytesMut),
    Shutdown(SplitStream<Framed<TcpStream>>),
}

struct SocketTask {
    handle: Handle,
    stream_rx: Option<SplitStream<Framed<TcpStream>>>,
    stream_tx: Option<SplitSink<Framed<TcpStream>>>,
    write_queue: BTreeMap<Priority, VecDeque<(Instant, BytesMut)>>,
    write_rx: UnboundedReceiver<TaskMsg>,
}

impl<M: 'static> Socket<M> {
    /// Wraps a `TcpStream` and turns it into a `Socket`.
    pub fn wrap_tcp(handle: &Handle, stream: TcpStream, peer_addr: SocketAddr) -> Socket<M> {
        const MAX_HEADER_SIZE: usize = 8;
        let framed = {
            length_delimited::Builder::new()
            .max_frame_length(MAX_PAYLOAD_SIZE + MAX_HEADER_SIZE)
            .new_framed(stream)
        };
        let (stream_tx, stream_rx) = framed.split();
        let (write_tx, write_rx) = mpsc::unbounded();
        let task = SocketTask {
            handle: handle.clone(),
            stream_tx: Some(stream_tx),
            stream_rx: None,
            write_queue: BTreeMap::new(),
            write_rx: write_rx,
        };
        handle.spawn({
            task
            .map_err(|e| {
                error!("Socket task failed!: {}", e);
            })
        });
        let inner = Inner {
            stream_rx: Some(stream_rx),
            write_tx: write_tx,
            peer_addr: peer_addr,
        };
        Socket {
            inner: Some(inner),
            _ph: PhantomData,
        }
    }

    /// Get the address of the remote peer (if the socket is still active).
    pub fn peer_addr(&self) -> Result<SocketAddr, SocketError> {
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
}

impl Drop for Inner {
    fn drop(&mut self) {
        let stream_rx = unwrap!(self.stream_rx.take());
        let _ = self.write_tx.unbounded_send(TaskMsg::Shutdown(stream_rx));
    }
}

impl<M> Stream for Socket<M>
where
    M: Serialize + DeserializeOwned
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
                None => return Err(SocketError::Destroyed),
            };
            let msg = deserialise(&data[..])?;
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
    M: Serialize + DeserializeOwned
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
        let mut data = Vec::with_capacity(MAX_PAYLOAD_SIZE);
        unwrap!(serialise_into(&msg, &mut data));
        data.shrink_to_fit();
        let data = BytesMut::from(data);
        let _ = inner.write_tx.unbounded_send(TaskMsg::Send(priority, data));
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, SocketError> {
        Ok(Async::Ready(()))
    }
}

impl Future for SocketTask {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<()>> {
        let now = Instant::now();
        loop {
            match unwrap!(self.write_rx.poll()) {
                Async::Ready(Some(TaskMsg::Send(priority, data))) => {
                    let queue = self.write_queue.entry(priority).or_insert_with(|| VecDeque::new());
                    queue.push_back((now, data));
                },
                Async::Ready(Some(TaskMsg::Shutdown(stream_rx))) => {
                    self.stream_rx = Some(stream_rx);
                    break;
                },
                Async::Ready(None) => break,
                Async::NotReady => break,
            }
        };

        let expired_keys: Vec<u8> = self.write_queue
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
        'outer: for (_, queue) in self.write_queue.iter_mut() {
            while let Some((time, msg)) = queue.pop_front() {
                match unwrap!(self.stream_tx.as_mut()).start_send(msg)? {
                    AsyncSink::Ready => (),
                    AsyncSink::NotReady(msg) => {
                        queue.push_front((time, msg));
                        all_messages_sent = false;
                        break 'outer;
                    },
                }
            }
        }

        if let Async::Ready(()) = unwrap!(self.stream_tx.as_mut()).poll_complete()? {
            if all_messages_sent {
                if let Some(stream_rx) = self.stream_rx.take() {
                    let stream_tx = unwrap!(self.stream_tx.take());
                    let tcp_stream = unwrap!(stream_rx.reunite(stream_tx)).into_inner();
                    tcp_stream.shutdown(Shutdown::Write)?;
                    let timeout = Timeout::new(Duration::from_secs(1), &self.handle)?;
                    self.handle.spawn({
                        timeout
                        .map(move |()| drop(tcp_stream))
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
    use priv_prelude::*;

    use env_logger;
    use tokio_core::reactor::Core;
    use rand::{self, Rng};

    use util;

    #[test]
    fn test_socket() {
        let _logger = env_logger::init();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();
        let res: Result<_, Void> = core.run(future::lazy(move || {
            let listener = unwrap!(TcpListener::bind(&addr!("0.0.0.0:0"), &handle));
            let addr = unwrap!(listener.local_addr());

            let num_msgs = 1000;
            let mut msgs = Vec::with_capacity(num_msgs);
            for _ in 0..num_msgs {
                let size = rand::thread_rng().gen_range(0, 10000);
                let data = util::random_vec(size);
                let msg = data;
                msgs.push(msg);
            }

            let msgs_send: Vec<(Priority, Vec<_>)> = msgs.iter().cloned().map(|m| (1, m)).collect();

            let handle0 = handle.clone();
            let f0 = TcpStream::connect(&addr, &handle)
                .map_err(|err| SocketError::from(err))
                .and_then(move |stream| {
                    let socket = Socket::<Vec<u8>>::wrap_tcp(&handle0, stream, addr);
                    socket
                    .send_all(stream::iter_ok::<_, SocketError>(msgs_send))
                    .map(|(_, _)| ())
                });

            let handle1 = handle.clone();
            let f1 = {
                listener
                .incoming()
                .into_future()
                .map_err(|(err, _)| SocketError::from(err))
                .and_then(move |(stream_opt, _)| {
                    let (stream, addr) = unwrap!(stream_opt);
                    let socket = Socket::<Vec<u8>>::wrap_tcp(&handle1, stream, addr);
                    socket 
                    .take(num_msgs as u64)
                    .collect()
                    .map(move |msgs_recv| {
                        assert!(msgs_recv == msgs);
                    })
                })
            };

            f0
            .join(f1)
            .and_then(|((), ())| Ok(()))
            .map_err(|e| panic!(e))
        }));
        unwrap!(res);
    }
}

