// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Tokio compatible in-memory stream implementation. Helpful for testing.

// TODO(povilas): move to future_utils crate - this module is generic and highly reusable.

use priv_prelude::*;
use std::cmp;
use std::io::{self, Read, Write};

/// In-memory stream implementing `AsyncWrite + AsyncRead`. This stream is not connected with
/// any other stream. Meaning what you write to the stream you can later read from it.
#[derive(Default, Debug)]
pub struct EchoStream {
    buf: Vec<u8>,
    shutdown: bool,
}

impl Read for EchoStream {
    /// Reads as much data as possible to the given buffer and removes that data from internal
    /// buffer.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.buf.is_empty() {
            if self.shutdown {
                return Ok(0);
            } else {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }

        let bytes_to_read = cmp::min(self.buf.len(), buf.len());
        buf.iter_mut()
            .zip(self.buf.drain(..bytes_to_read))
            .for_each(|(dst, src)| *dst = src);
        Ok(bytes_to_read)
    }
}

impl Write for EchoStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for EchoStream {}

impl AsyncWrite for EchoStream {
    /// Analogous to sending FIN to myself.
    /// This will unblock `read()` calls which will get 0 as result value.
    fn shutdown(&mut self) -> io::Result<Async<()>> {
        self.shutdown = true;
        Ok(Async::Ready(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod echostream {
        use super::*;
        use tokio_core::reactor::Core;
        use tokio_io;

        mod read {
            use super::*;

            mod when_stream_is_empty {
                use super::*;

                #[test]
                fn when_stream_is_open_it_returns_would_block_error() {
                    let mut stream = EchoStream::default();

                    let mut data = [0; 4];
                    let res = stream.read(&mut data);

                    match res {
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
                        res => panic!("Unexpected read() result: {:?}", res),
                    }
                }

                #[test]
                fn when_stream_is_closed_it_returns_0() {
                    let mut stream = EchoStream::default();
                    stream.shutdown = true;

                    let mut data = [0; 4];
                    let bytes_read = unwrap!(stream.read(&mut data));

                    assert_eq!(bytes_read, 0);
                }
            }

            #[test]
            fn it_removes_bytes_read_from_internal_buffer() {
                let mut stream = EchoStream::default();
                stream.buf.extend_from_slice(b"data1");

                let mut data = [0; 8];
                let _ = unwrap!(stream.read(&mut data));

                assert!(stream.buf.is_empty());
            }

            #[test]
            fn when_given_buffer_is_smaller_than_internal_one_it_reads_in_chunks() {
                let mut stream = EchoStream::default();
                stream.buf.extend_from_slice(b"data1");
                stream.buf.extend_from_slice(b"data2");

                let mut data = [0; 5];
                let _ = unwrap!(stream.read(&mut data));
                assert_eq!(&data, b"data1");

                let _ = unwrap!(stream.read(&mut data));
                assert_eq!(&data, b"data2");
            }
        }

        #[test]
        fn writes_reads_are_reflective() {
            let mut stream = EchoStream::default();
            let _ = unwrap!(stream.write(b"data1"));
            let _ = unwrap!(stream.write(b"data2"));

            let mut data = [0; 16];
            let bytes_read = unwrap!(stream.read(&mut data));

            assert_eq!(bytes_read, 10);
            assert_eq!(data[..10], b"data1data2"[..10]);
        }

        #[test]
        fn async_writes_reads() {
            let mut evloop = unwrap!(Core::new());
            let stream = EchoStream::default();

            let write_read = tokio_io::io::write_all(stream, b"data1")
                .and_then(|(stream, _)| tokio_io::io::write_all(stream, b"data2"))
                .and_then(|(stream, _)| tokio_io::io::shutdown(stream))
                .and_then(|stream| tokio_io::io::read_to_end(stream, Vec::new()))
                .and_then(|(_stream, data)| Ok(data));
            let data_read = unwrap!(evloop.run(write_read));

            assert_eq!(data_read.len(), 10);
            assert_eq!(data_read[..10], b"data1data2"[..10]);
        }
    }
}
