use utp::UtpSocket;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::mpsc;
use std::thread;
use std::io::{Read, ErrorKind};
use std::io;
use std::net::SocketAddr;
use std::collections::VecDeque;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::serialise;
use event::WriteEvent;

const CHECK_FOR_NEW_WRITES_INTERVAL_MS: u64 = 50;
const BUFFER_SIZE: usize = 1000;

pub struct UtpWrapper {
    input: Receiver<Vec<u8>>,
    unread_bytes: VecDeque<u8>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    _thread_joiner: RaiiThreadJoiner,
}

impl UtpWrapper {
    pub fn wrap(socket: UtpSocket, output_rx: Receiver<WriteEvent>) -> io::Result<UtpWrapper> {
        let (input_tx, input_rx) = mpsc::channel();
        let peer_addr = try!(socket.peer_addr());
        let local_addr = try!(socket.local_addr());

        let thread_handle = unwrap_result!(thread::Builder::new()
                .name("rust-utp multiplexer".to_owned())
                .spawn(move || {
                    let mut socket = socket;
                    socket.set_read_timeout(Some(CHECK_FOR_NEW_WRITES_INTERVAL_MS));
                    'outer: loop {
                        let mut buf = [0; BUFFER_SIZE];
                        match socket.recv_from(&mut buf[..]) {
                            Ok((0, _src)) => {
                                info!("Gracefully closing uTP connection");
                                break;
                            }
                            Ok((amt, _src)) => {
                                let buf = &buf[..amt];
                                match input_tx.send(Vec::from(buf)) {
                                    Ok(()) => (),
                                    Err(mpsc::SendError(_)) => {
                                        debug!("User channel closed. Closing uTP connection");
                                        break 'outer;
                                    }
                                }
                            }
                            Err(ref e) if e.kind() == ErrorKind::TimedOut => {
                                // This extra loop ensures all pending messages are sent
                                // before we try to read again.
                                let mut send_keepalive = true;
                                loop {
                                    match output_rx.try_recv() {
                                        Ok(WriteEvent::Write(msg)) => {
                                            send_keepalive = false;
                                            let data = unwrap_result!(serialise(&msg));
                                            if let Err(err) = socket.send_to(&data) {
                                                error!("Error sending: {:?}", err);
                                                break 'outer;
                                            }
                                        }
                                        Ok(WriteEvent::Shutdown) => {
                                            debug!("Shutdown requested. Closing socket");
                                            break 'outer;
                                        }
                                        Err(TryRecvError::Disconnected) => {
                                            debug!("User channel closed. Closing uTP connection");
                                            break 'outer;
                                        }
                                        Err(TryRecvError::Empty) => break,
                                    }
                                }
                                if send_keepalive {
                                    socket.send_keepalive();
                                }
                            }
                            Err(err) => {
                                error!("Error receiving: {:?}", err);
                                break;
                            }
                        }
                    }
                }));

        Ok(UtpWrapper {
            input: input_rx,
            unread_bytes: VecDeque::new(),
            peer_addr: peer_addr,
            local_addr: local_addr,
            _thread_joiner: RaiiThreadJoiner::new(thread_handle),
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
        use std;

        let written = {
            let (unread_front, unread_back) = self.unread_bytes.as_slices();
            if unread_front.len() > 0 {
                let read_len = std::cmp::min(buf.len(), unread_front.len());
                let target = &mut buf[..read_len];
                let src = &unread_front[..read_len];
                target.clone_from_slice(src);
                read_len
            } else if unread_back.len() > 0 {
                let read_len = std::cmp::min(buf.len(), unread_back.len());
                let target = &mut buf[..read_len];
                let src = &unread_back[..read_len];
                target.clone_from_slice(src);
                read_len
            } else {
                0
            }
        };
        if written > 0 {
            let _ = self.unread_bytes.drain(..written);
            return Ok(written);
        }

        let recved = try!(self.input
                              .recv()
                              .or_else(|e| Err(io::Error::new(ErrorKind::BrokenPipe, e))));
        let read_len = std::cmp::min(recved.len(), buf.len());
        let target = &mut buf[..read_len];
        let src = &recved[..read_len];
        target.clone_from_slice(src);
        self.unread_bytes.extend(&recved[read_len..]);
        Ok(read_len)
    }
}
