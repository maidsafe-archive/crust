// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Cursor, ErrorKind, Read, Write};
use std::mem;
use std::net::SocketAddr;
use std::time::Instant;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use common::{CommonError, Core, MAX_PAYLOAD_SIZE, Priority, Result};
use maidsafe_utilities::serialisation::{deserialise_from, serialise_into};
use mio::{EventLoop, EventSet, Evented, PollOpt, Selector, Token};
use mio::tcp::TcpStream;
use rustc_serialize::{Decodable, Encodable};

// Maximum age of a message waiting to be sent. If a message is older, the queue is dropped.
#[cfg(test)]
pub const MAX_MSG_AGE_SECS: u64 = 60;
#[cfg(not(test))]
const MAX_MSG_AGE_SECS: u64 = 60;

pub struct Socket {
    stream: TcpStream,
    read_buffer: Vec<u8>,
    read_len: usize,
    write_queue: BTreeMap<Priority, VecDeque<(Instant, Vec<u8>)>>,
    current_write: Option<Vec<u8>>,
}

impl Socket {
    pub fn connect(addr: &SocketAddr) -> Result<Self> {
        let stream = try!(TcpStream::connect(addr));
        Ok(Self::wrap(stream))
    }

    pub fn wrap(stream: TcpStream) -> Self {
        Socket {
            stream: stream,
            read_buffer: Vec::new(),
            read_len: 0,
            write_queue: BTreeMap::new(),
            current_write: None,
        }
    }

    pub fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(try!(self.stream.peer_addr()))
    }

    // Read message from the socket. Call this from inside the `ready` handler.
    //
    // Returns:
    //   - Ok(Some(data)): data has been successfuly read from the socket
    //   - Ok(None):       there is not enough data in the socket. Call `read`
    //                     again in the next invocation of the `ready` handler.
    //   - Err(error):     there was an error reading from the socket.
    pub fn read<T: Decodable>(&mut self) -> Result<Option<T>> {
        if let Some(message) = try!(self.read_from_buffer()) {
            return Ok(Some(message));
        }

        // the mio reading window is max at 64k (64 * 1024)
        let mut buffer = [0; 65536];

        match self.stream.read(&mut buffer) {
            Ok(bytes_read) => {
                self.read_buffer.extend_from_slice(&buffer[0..bytes_read]);
                self.read_from_buffer()
            }

            Err(error) => {
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::Interrupted {
                    Ok(None)
                } else {
                    Err(From::from(error))
                }
            }
        }
    }

    fn read_from_buffer<T: Decodable>(&mut self) -> Result<Option<T>> {
        let u32_size = mem::size_of::<u32>();

        if self.read_len == 0 {
            if self.read_buffer.len() < u32_size {
                return Ok(None);
            }

            self.read_len = try!(Cursor::new(&self.read_buffer)
                .read_u32::<LittleEndian>()) as usize;

            if self.read_len > MAX_PAYLOAD_SIZE {
                return Err(CommonError::PayloadSizeProhibitive);
            }

            self.read_buffer = self.read_buffer[u32_size..].to_owned();
        }

        if self.read_len > self.read_buffer.len() {
            return Ok(None);
        }

        let result = try!(deserialise_from(&mut Cursor::new(&self.read_buffer)));

        self.read_buffer = self.read_buffer[self.read_len..].to_owned();
        self.read_len = 0;

        Ok(Some(result))
    }

    // Write a message to the socket.
    //
    // Returns:
    //   - Ok(true):   the message has been successfuly written.
    //   - Ok(false):  the message has been queued, but not yet fully written.
    //                 Write event is already scheduled for next time.
    //   - Err(error): there was an error while writing to the socket.
    pub fn write<T: Encodable>(&mut self,
                               el: &mut EventLoop<Core>,
                               token: Token,
                               msg: Option<(T, Priority)>)
                               -> ::Res<bool> {
        let expired_keys: Vec<u8> = self.write_queue
            .iter()
            .skip_while(|&(&priority, ref queue)| {
                priority == 0 || // Don't drop messages with priority 0.
                queue.front().map_or(false, |&(ref timestamp, _)| {
                    timestamp.elapsed().as_secs() <= MAX_MSG_AGE_SECS
                })
            })
            .map(|(&priority, _)| priority)
            .collect();
        let dropped_msgs: usize = expired_keys.iter()
            .filter_map(|priority| self.write_queue.remove(priority))
            .map(|queue| queue.len())
            .fold(0, |s, len| s + len); // TODO: Use `sum` once that's stable.
        if dropped_msgs > 0 {
            debug!("Insufficient bandwidth. Dropping {} messages with priority >= {}.",
                   dropped_msgs,
                   expired_keys[0]);
        }

        if let Some((msg, priority)) = msg {
            let mut data = Cursor::new(Vec::with_capacity(mem::size_of::<u32>()));

            let _ = data.write_u32::<LittleEndian>(0);

            try!(serialise_into(&msg, &mut data));

            let len = data.position() - mem::size_of::<u32>() as u64;
            data.set_position(0);
            try!(data.write_u32::<LittleEndian>(len as u32));

            let entry =
                self.write_queue.entry(priority).or_insert_with(|| VecDeque::with_capacity(10));
            entry.push_back((Instant::now(), data.into_inner()));
        }

        if self.current_write.is_none() {
            let (key, (_time_stamp, data), empty) = match self.write_queue.iter_mut().next() {
                Some((key, queue)) => {
                    (*key, queue.pop_front().expect("Logic Error - Queue pop"), queue.is_empty())
                }
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
                       error.kind() == ErrorKind::Interrupted {
                        self.current_write = Some(data);
                    } else {
                        return Err(From::from(error));
                    }
                }
            }
        }

        let done = self.current_write.is_none() && self.write_queue.is_empty();

        let event_set = if done {
            EventSet::error() | EventSet::hup() | EventSet::readable()
        } else {
            EventSet::error() | EventSet::hup() | EventSet::readable() | EventSet::writable()
        };

        try!(el.reregister(self, token, event_set, PollOpt::edge()));

        Ok(done)
    }

    #[cfg(test)]
    pub fn take_socket_error(&self) -> io::Result<()> {
        self.stream.take_socket_error()
    }
}

impl Evented for Socket {
    fn register(&self,
                selector: &mut Selector,
                token: Token,
                interest: EventSet,
                opts: PollOpt)
                -> io::Result<()> {
        self.stream.register(selector, token, interest, opts)
    }

    fn reregister(&self,
                  selector: &mut Selector,
                  token: Token,
                  interest: EventSet,
                  opts: PollOpt)
                  -> io::Result<()> {
        self.stream.reregister(selector, token, interest, opts)
    }

    fn deregister(&self, selector: &mut Selector) -> io::Result<()> {
        self.stream.deregister(selector)
    }
}
