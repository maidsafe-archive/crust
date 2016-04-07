use utp::UtpSocket;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::mpsc;
use std::io::{Read, ErrorKind};
use std::io;
use std::net::SocketAddr;
use std::collections::VecDeque;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::{deserialise, serialise};
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
    pub fn wrap(mut socket: UtpSocket, output_rx: Receiver<WriteEvent>) -> io::Result<UtpWrapper> {
        let (input_tx, input_rx) = mpsc::channel();
        let peer_addr = try!(socket.peer_addr());
        let local_addr = try!(socket.local_addr());

        let joiner = thread!("Rust-uTP-Multiplexer", move || {
            const MAX_NO_READ_INTERVAL_MS: u64 = 9 * 1000;
            const HEARTBEAT_INTERVAL: u64 = MAX_NO_READ_INTERVAL_MS / 3;

            const MAX_NO_READ_COUNT: u64 = MAX_NO_READ_INTERVAL_MS /
                                           CHECK_FOR_NEW_WRITES_INTERVAL_MS;
            const SEND_HEARTBEAT_NO_READ_COUNT: u64 = HEARTBEAT_INTERVAL /
                                                      CHECK_FOR_NEW_WRITES_INTERVAL_MS;

            let mut no_read_count = 0;

            #[derive(RustcEncodable, RustcDecodable)]
            enum WireMessage {
                HeartbeatPing,
                HeartbeatPong,
            }

            socket.set_read_timeout(Some(CHECK_FOR_NEW_WRITES_INTERVAL_MS));
            'outer: loop {
                let mut buf = [0; BUFFER_SIZE];

                match socket.recv_from(&mut buf[..]) {
                    Ok((0, _src)) => {
                        debug!("Gracefully closing uTP connection");
                        break;
                    }
                    Ok((amt, _src)) => {
                        no_read_count = 0;
                        let buf = &buf[..amt];
                        match deserialise(buf) {
                            Ok(WireMessage::HeartbeatPing) => {
                                let data = unwrap_result!(serialise(&WireMessage::HeartbeatPong));
                                if let Err(err) = socket.send_to(&data) {
                                    error!("Error sending: {:?}", err);
                                    break 'outer;
                                }
                                trace!("HeartbeatPong Sent");
                            }
                            Ok(WireMessage::HeartbeatPong) => (),
                            _ => {
                                match input_tx.send(Vec::from(buf)) {
                                    Ok(()) => (),
                                    Err(mpsc::SendError(_)) => {
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == ErrorKind::TimedOut => {
                        // This extra loop ensures all pending messages are sent
                        // before we try to read again.
                        loop {
                            match output_rx.try_recv() {
                                Ok(WriteEvent::Write(msg)) => {
                                    let data = unwrap_result!(serialise(&msg));
                                    if let Err(err) = socket.send_to(&data) {
                                        error!("Error sending: {:?}", err);
                                        break 'outer;
                                    }
                                }
                                Ok(WriteEvent::Shutdown) => break 'outer,
                                Err(TryRecvError::Disconnected) => break 'outer,
                                Err(TryRecvError::Empty) => {
                                    no_read_count += 1;
                                    if no_read_count > MAX_NO_READ_COUNT {
                                        debug!("Closing uTP connection due to heartbeat failure");
                                        break 'outer;
                                    } else if no_read_count % SEND_HEARTBEAT_NO_READ_COUNT == 0 {
                                        let data =
                                            unwrap_result!(serialise(&WireMessage::HeartbeatPing));
                                        if let Err(err) = socket.send_to(&data) {
                                            error!("Error sending: {:?}", err);
                                            break 'outer;
                                        }
                                        trace!("HeartbeatPing Sent");
                                    }

                                    break;
                                }
                            }
                        }
                    }
                    Err(err) => {
                        error!("Error receiving: {:?}", err);
                        break;
                    }
                }
            }
        });

        Ok(UtpWrapper {
            input: input_rx,
            unread_bytes: VecDeque::new(),
            peer_addr: peer_addr,
            local_addr: local_addr,
            _thread_joiner: RaiiThreadJoiner::new(joiner),
        })
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr.clone()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr.clone()
    }
}

// TODO(canndrew): Remove this once clone_from_slice in the standard library becomes stable.
fn clone_from_slice<T: Clone>(target: &mut [T], src: &[T]) {
    for (t, s) in target.into_iter().zip(src.into_iter()) {
        *t = s.clone();
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
                clone_from_slice(target, src);
                read_len
            } else if unread_back.len() > 0 {
                let read_len = std::cmp::min(buf.len(), unread_back.len());
                let target = &mut buf[..read_len];
                let src = &unread_back[..read_len];
                clone_from_slice(target, src);
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
        clone_from_slice(target, src);
        self.unread_bytes.extend(&recved[read_len..]);
        Ok(read_len)
    }
}
