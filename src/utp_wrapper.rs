use utp::UtpSocket;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::mpsc;
use std::thread;
use std::io::{Read, ErrorKind};
use std::io;
use std::net::SocketAddr;
use maidsafe_utilities::thread::RaiiThreadJoiner;

const CHECK_FOR_NEW_WRITES_INTERVAL_MS: u64 = 50;
const BUFFER_SIZE: usize = 1000;

pub struct UtpWrapper {
    input: Receiver<Vec<u8>>,
    unread_bytes: Vec<u8>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    _thread_joiner: RaiiThreadJoiner
}

impl UtpWrapper {
    pub fn wrap(socket: UtpSocket, output_rx: Receiver<Vec<u8>>)
        -> io::Result<UtpWrapper>
    {
        let (input_tx, input_rx) = mpsc::channel();
        let peer_addr = try!(socket.peer_addr());
        let local_addr = try!(socket.local_addr());

        let thread_handle = thread::Builder::new()
                                .name("rust-utp multiplexer".to_owned())
                                .spawn(move || {
            let mut socket = socket;
            socket.set_read_timeout(Some(CHECK_FOR_NEW_WRITES_INTERVAL_MS));
            'outer: loop {
                let mut buf = [0; BUFFER_SIZE];
                match socket.recv_from(&mut buf) {
                    Ok((0, _src)) => break,
                    Ok((amt, _src)) => {
                        let buf = &buf[..amt];
                        let _ = input_tx.send(Vec::from(buf));
                    }
                    Err(ref e) if e.kind() == ErrorKind::TimedOut => {
                        // This extra loop ensures all pending messages are sent
                        // before we try to read again.
                        loop {
                            match output_rx.try_recv() {
                                Ok(v) => {
                                    if let Err(e) = socket.send_to(&v[..]) {
                                        panic!("VINIPSMAKER, listen2: {:?}", e);
                                    }
                                }
                                Err(TryRecvError::Disconnected) => break 'outer,
                                Err(TryRecvError::Empty) => break,
                            }
                        }
                    }
                    Err(e) => {
                        panic!("VINIPSMAKER, listen: {:?}", e);
                    }
                }
            }
        }).unwrap();

        Ok(UtpWrapper {
            input: input_rx,
            unread_bytes: Vec::new(),
            peer_addr: peer_addr,
            local_addr: local_addr,
            _thread_joiner: RaiiThreadJoiner::new(thread_handle)
        })
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr.clone()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr.clone()
    }
}

impl Read for UtpWrapper {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        for (idx, e) in self.unread_bytes.iter().take(buf.len()).enumerate() {
            buf[idx] = *e;
            written += 1;
        }

        {
            let mut n = written;
            while n != 0 {
                let _ = self.unread_bytes.remove(0);
                n -= 1;
            }
        }

        // We send all read bytes before issuing another request because
        // application logic may require these bytes before it's possible to
        // get/generate the next ones.
        if written != 0 {
            return Ok(written);
        }

        let mut buf_mut = &mut buf[written..];
        let recved = try!(self.input
                              .recv()
                              .or_else(|e| Err(io::Error::new(ErrorKind::BrokenPipe, e))));
        for (idx, e) in recved.iter().take(buf_mut.len()).enumerate() {
            buf_mut[idx] = *e;
            written += 1;
        }
        self.unread_bytes.extend(recved.into_iter().skip(buf_mut.len()));
        Ok(written)
    }
}
