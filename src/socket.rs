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

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use maidsafe_utilities::serialisation::{deserialise_from,
                                        serialise_into,
                                        SerialisationError};
use mio::{Evented, EventSet, PollOpt, Selector, Token};
use mio::tcp::{Shutdown, TcpStream};
use rustc_serialize::{Decodable, Encodable};
use std::collections::VecDeque;
use std::io::{self, Cursor, ErrorKind, Read, Write};
use std::mem;
use std::net::SocketAddr;

// Wrapper over raw TcpStream, which automatically handles buffering and
// (de)serialization.
pub struct Socket {
    stream: TcpStream,
    read_buffer: Vec<u8>,
    read_len: usize,
    write_queue: VecDeque<Vec<u8>>,
}

impl Socket {
    pub fn connect(addr: &SocketAddr) -> Result<Self, SocketError> {
        let stream = try!(TcpStream::connect(addr));
        Ok(Self::wrap(stream))
    }

    pub fn wrap(stream: TcpStream) -> Self {
        Socket {
            stream: stream,
            read_buffer: Vec::new(),
            read_len: 0,
            write_queue: VecDeque::new(),
        }
    }

    // Read message from the socket. Call this from inside the `ready` handler.
    //
    // Returns:
    //   - Ok(Some(data)): data has been successfuly read from the socket
    //   - Ok(None):       there is not enough data in the socket. Call `read`
    //                     again in the next invocation of the `ready` handler.
    //   - Err(error):     there was an error reading from the socket.
    pub fn read<T: Decodable>(&mut self) -> Result<Option<T>, SocketError> {
        // If there is something in the read buffer already, retrieve it without
        // hitting the socket at all.
        if let Some(message) = try!(self.read_from_buffer()) {
            return Ok(Some(message))
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

    fn read_from_buffer<T: Decodable>(&mut self) -> Result<Option<T>, SocketError> {
        // TODO: use some kind of ring buffer here.
        let u32_size = mem::size_of::<u32>();

        // The length of the message is encoded in the first 4 bytes:
        if self.read_len == 0 {
            if self.read_buffer.len() < u32_size { return Ok(None); }

            self.read_len = try!(Cursor::new(&self.read_buffer).read_u32::<LittleEndian>()) as usize;
            self.read_buffer = self.read_buffer[u32_size..].to_owned();
        }

        // There is not enough data in the read buffer, signal the caller to
        // call `read` again in the next ready handler.
        if self.read_len > self.read_buffer.len() { return Ok(None); }

        // TODO: enforce size limit
        let result = try!(deserialise_from(&mut Cursor::new(&self.read_buffer)));

        self.read_buffer = self.read_buffer[self.read_len..].to_owned();
        self.read_len = 0;

        Ok(Some(result))
    }

    // Write a message to the socket.
    //
    // Returns:
    //   - Ok(true):   the message has been successfuly written.
    //   - Ok(false):  the message (or part of it) has been queued. Schedule a
    //                 write event and call `flush` to finish the write in the
    //                 next ready handler.
    //   - Err(error): there was an error while writing to the socket.
    pub fn write<T: Encodable>(&mut self, message: T) -> Result<bool, SocketError> {
        let mut data = Cursor::new(Vec::with_capacity(mem::size_of::<u32>()));

        // Preallocate space for the message length at the beginning of the
        // data buffer.
        let _ = data.write_u32::<LittleEndian>(0);

        // Serialize the message into the rest of the data buffer.
        try!(serialise_into(&message, &mut data));

        // Rewind the cursor to write the actual length to the beginning.
        let len = data.position() - mem::size_of::<u32>() as u64;
        data.set_position(0);
        try!(data.write_u32::<LittleEndian>(len as u32));

        self.write_queue.push_back(data.into_inner());
        self.flush()
    }

    // Flush previous writes. Call this from inside the `ready` handler.
    //
    // Returns:
    //   - Ok(true):   all queued data has been written.
    //   - Ok(false):  more stuff remains to be written. Call `flush` again in
    //                 the next invocation of the ready handler.
    //   - Err(error): there was an error while writing to the socket.
    pub fn flush(&mut self) -> Result<bool, SocketError> {
        while let Some(mut data) = self.write_queue.pop_front() {
            match self.stream.write(&data) {
                Ok(bytes_written) => {
                    if bytes_written < data.len() {
                        data = data[bytes_written..].to_owned();
                        self.write_queue.push_front(data);
                        return Ok(false);
                    }
                }

                Err(error) => {
                    if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::Interrupted {
                        self.write_queue.push_front(data);
                        return Ok(false)
                    } else {
                        return Err(From::from(error))
                    }
                }
            }
        }

        Ok(true)
    }

    /// Shut down the socket (both reading and writing).
    pub fn shutdown(&self) -> Result<(), SocketError> {
        Ok(try!(self.stream.shutdown(Shutdown::Both)))
    }
}

impl Evented for Socket {
    fn register(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
        self.stream.register(selector, token, interest, opts)
    }

    fn reregister(&self, selector: &mut Selector, token: Token, interest: EventSet, opts: PollOpt) -> io::Result<()> {
        self.stream.reregister(selector, token, interest, opts)
    }

    fn deregister(&self, selector: &mut Selector) -> io::Result<()> {
        self.stream.deregister(selector)
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum SocketError {
        Io(err: io::Error) {
            description("IO error")
            display("IO error: {}", err)
            cause(err)
            from()
        }

        Serialisation(err: SerialisationError) {
            description("Serialisation error")
            display("Serialisation error: {}", err)
            cause(err)
            from()
        }
    }
}

// TODO: write unit tests for Socket
