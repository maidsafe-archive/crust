// Copyright 2016 MaidSafe.net limited.
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

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use common::{CommonError, MAX_PAYLOAD_SIZE, MSG_DROP_PRIORITY, Priority, Result};
use maidsafe_utilities::serialisation::{deserialise_from, serialise_into};
use mio::{Evented, Poll, PollOpt, Ready, Token};
use mio::tcp::TcpStream;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Cursor, ErrorKind, Read, Write};
use std::mem;
use std::net::{Shutdown, SocketAddr};
use std::time::Instant;

/// Maximum age of a message waiting to be sent. If a message is older, the queue is dropped.
const MAX_MSG_AGE_SECS: u64 = 60;

pub struct Socket {
    inner: Option<SockInner>,
}

impl Socket {
    pub fn connect(addr: &SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Self::wrap(stream))
    }

    pub fn wrap(stream: TcpStream) -> Self {
        Socket {
            inner: Some(SockInner {
                stream: stream,
                read_buffer: Vec::new(),
                read_len: 0,
                write_queue: BTreeMap::new(),
                current_write: None,
            }),
        }
    }

    pub fn peer_addr(&self) -> Result<SocketAddr> {
        let inner = self.inner.as_ref().ok_or(CommonError::UninitialisedSocket)?;
        Ok(inner.stream.peer_addr()?)
    }

    pub fn take_error(&self) -> Result<Option<io::Error>> {
        let inner = self.inner.as_ref().ok_or(CommonError::UninitialisedSocket)?;
        Ok(inner.stream.take_error()?)
    }

    // Read message from the socket. Call this from inside the `ready` handler.
    //
    // Returns:
    //   - Ok(Some(data)): data has been successfully read from the socket
    //   - Ok(None):       there is not enough data in the socket. Call `read`
    //                     again in the next invocation of the `ready` handler.
    //   - Err(error):     there was an error reading from the socket.
    pub fn read<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        let inner = self.inner.as_mut().ok_or(CommonError::UninitialisedSocket)?;
        inner.read()
    }

    // Write a message to the socket.
    //
    // Returns:
    //   - Ok(true):   the message has been successfully written.
    //   - Ok(false):  the message has been queued, but not yet fully written.
    //                 Write event is already scheduled for next time.
    //   - Err(error): there was an error while writing to the socket.
    pub fn write<T: Serialize>(
        &mut self,
        poll: &Poll,
        token: Token,
        msg: Option<(T, Priority)>,
    ) -> ::Res<bool> {
        let inner = self.inner.as_mut().ok_or(CommonError::UninitialisedSocket)?;
        inner.write(poll, token, msg)
    }
}

impl Default for Socket {
    fn default() -> Self {
        Socket { inner: None }
    }
}

impl Evented for Socket {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        let inner = self.inner.as_ref().ok_or_else(|| {
            io::Error::new(
                ErrorKind::Other,
                format!("{}", CommonError::UninitialisedSocket),
            )
        })?;
        inner.register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        let inner = self.inner.as_ref().ok_or_else(|| {
            io::Error::new(
                ErrorKind::Other,
                format!("{}", CommonError::UninitialisedSocket),
            )
        })?;
        inner.reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        let inner = self.inner.as_ref().ok_or_else(|| {
            io::Error::new(
                ErrorKind::Other,
                format!("{}", CommonError::UninitialisedSocket),
            )
        })?;
        inner.deregister(poll)
    }
}

struct SockInner {
    stream: TcpStream,
    read_buffer: Vec<u8>,
    read_len: usize,
    write_queue: BTreeMap<Priority, VecDeque<(Instant, Vec<u8>)>>,
    current_write: Option<Vec<u8>>,
}

impl SockInner {
    // Read message from the socket. Call this from inside the `ready` handler.
    //
    // Returns:
    //   - Ok(Some(data)): data has been successfully read from the socket.
    //   - Ok(None):       there is not enough data in the socket. Call `read`
    //                     again in the next invocation of the `ready` handler.
    //   - Err(error):     there was an error reading from the socket.
    fn read<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        if let Some(message) = self.read_from_buffer()? {
            return Ok(Some(message));
        }

        // the mio reading window is max at 64k (64 * 1024)
        let mut buffer = [0; 65536];
        let mut is_something_read = false;

        loop {
            match self.stream.read(&mut buffer) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        let e = Err(CommonError::ZeroByteRead);
                        if is_something_read {
                            return match self.read_from_buffer() {
                                r @ Ok(Some(_)) | r @ Err(_) => r,
                                Ok(None) => e,
                            };
                        } else {
                            return e;
                        }
                    }
                    self.read_buffer.extend_from_slice(&buffer[0..bytes_read]);
                    is_something_read = true;
                }
                Err(error) => {
                    return if error.kind() == ErrorKind::WouldBlock ||
                        error.kind() == ErrorKind::Interrupted
                    {
                        if is_something_read {
                            self.read_from_buffer()
                        } else {
                            Ok(None)
                        }
                    } else {
                        Err(From::from(error))
                    }
                }
            }
        }
    }

    fn read_from_buffer<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        let u32_size = mem::size_of::<u32>();

        if self.read_len == 0 {
            if self.read_buffer.len() < u32_size {
                return Ok(None);
            }

            self.read_len = Cursor::new(&self.read_buffer).read_u32::<LittleEndian>()? as usize;

            if self.read_len > MAX_PAYLOAD_SIZE {
                return Err(CommonError::PayloadSizeProhibitive);
            }

            self.read_buffer = self.read_buffer[u32_size..].to_owned();
        }

        if self.read_len > self.read_buffer.len() {
            return Ok(None);
        }

        let result = deserialise_from(&mut Cursor::new(&self.read_buffer))?;

        self.read_buffer = self.read_buffer[self.read_len..].to_owned();
        self.read_len = 0;

        Ok(Some(result))
    }

    // Write a message to the socket.
    //
    // Returns:
    //   - Ok(true):   the message has been successfully written.
    //   - Ok(false):  the message has been queued, but not yet fully written.
    //                 Write event is already scheduled for next time.
    //   - Err(error): there was an error while writing to the socket.
    fn write<T: Serialize>(
        &mut self,
        poll: &Poll,
        token: Token,
        msg: Option<(T, Priority)>,
    ) -> ::Res<bool> {
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

        if let Some((msg, priority)) = msg {
            let mut data = Cursor::new(Vec::with_capacity(mem::size_of::<u32>()));

            let _ = data.write_u32::<LittleEndian>(0);

            serialise_into(&msg, &mut data)?;

            let len = data.position() - mem::size_of::<u32>() as u64;
            data.set_position(0);
            data.write_u32::<LittleEndian>(len as u32)?;

            let entry = self.write_queue.entry(priority).or_insert_with(|| {
                VecDeque::with_capacity(10)
            });
            entry.push_back((Instant::now(), data.into_inner()));
        }

        if self.current_write.is_none() {
            let (key, (_time_stamp, data), empty) = match self.write_queue.iter_mut().next() {
                Some((key, queue)) => (*key, unwrap!(queue.pop_front()), queue.is_empty()),
                None => return Ok(true),
            };
            if empty {
                let _ = self.write_queue.remove(&key);
            }
            self.current_write = Some(data);
        }

        if let Some(data) = self.current_write.take() {
            match self.stream.write(&data) {
                Ok(bytes_txd) => {
                    if bytes_txd < data.len() {
                        self.current_write = Some(data[bytes_txd..].to_owned());
                    }
                }
                Err(error) => {
                    if error.kind() == ErrorKind::WouldBlock ||
                        error.kind() == ErrorKind::Interrupted
                    {
                        self.current_write = Some(data);
                    } else {
                        return Err(From::from(error));
                    }
                }
            }
        }

        let done = self.current_write.is_none() && self.write_queue.is_empty();

        let event_set = if done {
            Ready::error() | Ready::hup() | Ready::readable()
        } else {
            Ready::error() | Ready::hup() | Ready::readable() | Ready::writable()
        };

        poll.reregister(self, token, event_set, PollOpt::edge())?;

        Ok(done)
    }
}

impl Evented for SockInner {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        self.stream.register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        self.stream.reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        self.stream.deregister(poll)
    }
}

impl Drop for SockInner {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
