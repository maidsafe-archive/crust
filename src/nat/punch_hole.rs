//! Implements tcp hole punching

use std::io;
use std::io::Cursor;
use std::collections::{HashMap, hash_map};
use std::any::Any;

use rand;
use net2;
use mio::tcp::{TcpStream, TcpListener};
use mio::{PollOpt, EventSet, Token, EventLoop};
use mio::{TryAccept, TryRead, TryWrite};
use byteorder::{ReadBytesExt, BigEndian};

use core::{Core, Context};
use core::state::State;
use nat::util::{new_reusably_bound_tcp_socket, tcp_builder_local_addr};
use nat::rendezvous_info::{PubRendezvousInfo, PrivRendezvousInfo};

const SECRET_LEN: usize = 4;
const NONCE_LEN: usize = 8;

/// An in-progress tcp hole punching attempt
pub struct PunchHole<F> {
    listener_token: Token,
    listener: TcpListener,
    writing_streams: HashMap<Token, WritingStream>,
    reading_streams: HashMap<Token, ReadingStream>,
    context: Context,
    our_secret: [u8; SECRET_LEN],
    their_secret: [u8; SECRET_LEN],
    best_stream: Option<(u64, TcpStream)>,
    finished: Option<F>,
}

struct WritingStream {
    stream: TcpStream,
    nonce: [u8; NONCE_LEN],
    bytes_written: usize,
}

struct ReadingStream {
    stream: TcpStream,
    nonce: [u8; NONCE_LEN],
    in_buff: [u8; SECRET_LEN + NONCE_LEN],
    bytes_read: usize,
}

impl<F> PunchHole<F>
        where F: FnOnce(&mut Core, &mut EventLoop<Core>, Option<TcpStream>) + Any
{
    /// Start tcp hole punching
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 socket: net2::TcpBuilder,
                 our_priv_info: PrivRendezvousInfo,
                 their_pub_info: PubRendezvousInfo,
                 finished: F
            ) -> io::Result<()>
    {
        let local_addr = try!(tcp_builder_local_addr(&socket));
        let mut sockets = Vec::new();
        for _ in 0..their_pub_info.endpoints.len() {
            let socket = try!(new_reusably_bound_tcp_socket(&local_addr));
            let socket = try!(socket.to_tcp_stream());
            sockets.push(socket);
        }

        let context = core.get_new_context();
        let token = core.get_new_token();
        let listener = try!(socket.listen(1));
        let listener = try!(TcpListener::from_listener(listener, &local_addr));
        try!(event_loop.register(&listener,
                                 token,
                                 EventSet::readable() | EventSet::error() | EventSet::hup(),
                                 PollOpt::level()));
        let _ = core.insert_context(token, context.clone());

        let mut streams = HashMap::new();
        for (socket, addr) in sockets.into_iter().zip(their_pub_info.endpoints) {
            let token = core.get_new_token();
            let stream = try!(TcpStream::connect_stream(socket, &addr));
            try!(event_loop.register(&stream,
                                     token,
                                     EventSet::writable() | EventSet::error() | EventSet::hup(),
                                     PollOpt::level()));
            let _ = core.insert_context(token, context.clone());
            let writing_stream = WritingStream {
                stream: stream,
                nonce: rand::random(),
                bytes_written: 0,
            };
            let _ = streams.insert(token, writing_stream);
        }

        let state = PunchHole {
            writing_streams: streams,
            reading_streams: HashMap::new(),
            listener_token: token,
            listener: listener,
            context: context.clone(),
            finished: Some(finished),
            our_secret: our_priv_info.secret,
            their_secret: their_pub_info.secret,
            best_stream: None,
        };
        let _ = core.insert_state(context, state);
        Ok(())
    }
}

impl<F> State for PunchHole<F>
        where F: FnOnce(&mut Core, &mut EventLoop<Core>, Option<TcpStream>) + Any
{
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             _event_set: EventSet)
    {
        if token == self.listener_token {
            match self.listener.accept() {
                Err(e) => {
                    debug!("Error accepting connection during hole punching: {}", e);
                    return;
                },
                Ok(None) => return,
                Ok(Some((stream, _))) => {
                    let token = core.get_new_token();
                    match event_loop.register(&stream,
                                              token,
                                              EventSet::writable() | EventSet::error() | EventSet::hup(),
                                              PollOpt::level())
                    {
                        Ok(()) => (),
                        Err(e) => debug!("Error reregistering stream: {}", e),
                    };
                    let writing_stream = WritingStream {
                        stream: stream,
                        nonce: rand::random(),
                        bytes_written: 0,
                    };
                    let _ = core.insert_context(token, self.context);
                    let _ = self.writing_streams.insert(token, writing_stream);
                },
            }
            return;
        }

        if let hash_map::Entry::Occupied(mut oe) = self.writing_streams.entry(token) {
            let res = {
                let writing_stream = oe.get_mut();
                let written = writing_stream.bytes_written;
                if written < SECRET_LEN {
                    match writing_stream.stream.try_write(&self.our_secret[written..]) {
                        Ok(Some(n)) => {
                            match writing_stream.stream.try_write(&writing_stream.nonce[..]) {
                                Ok(Some(m)) => Ok(Some(n + m)),
                                Ok(None) => Ok(Some(n)),
                                Err(e) => Err(e),
                            }
                        },
                        x => x,
                    }
                }
                else {
                    writing_stream.stream.try_write(&writing_stream.nonce[(written - SECRET_LEN)..])
                }
            };
            match res {
                Err(e) => {
                    debug!("Error writing stream during hole punching: {}", e);
                    let writing_stream = oe.remove();
                    match event_loop.deregister(&writing_stream.stream) {
                        Ok(()) => (),
                        Err(e) => debug!("Error deregistering socket: {}", e),
                    };
                    let _ = core.remove_context(token);
                },
                Ok(None) => {
                    return;
                }
                Ok(Some(0)) => {
                    let writing_stream = oe.remove();
                    let _ = core.remove_context(token);
                    match event_loop.deregister(&writing_stream.stream)
                    {
                        Ok(()) => (),
                        Err(e) => {
                            debug!("Error deregistering stream: {}", e);
                            return;
                        },
                    };
                },
                Ok(Some(n)) => {
                    oe.get_mut().bytes_written += n;
                    let written = oe.get_mut().bytes_written;
                    if written >= SECRET_LEN + NONCE_LEN {
                        let writing_stream = oe.remove();
                        match event_loop.reregister(&writing_stream.stream,
                                                    token,
                                                    EventSet::readable() | EventSet::error() | EventSet::hup(),
                                                    PollOpt::edge())
                        {
                            Ok(()) => (),
                            Err(e) => {
                                debug!("Error reregistering stream: {}", e);
                                let _ = core.remove_context(token);
                                return;
                            },
                        };
                        let reading_stream = ReadingStream {
                            stream: writing_stream.stream,
                            nonce: writing_stream.nonce,
                            in_buff: [0u8; SECRET_LEN + NONCE_LEN],
                            bytes_read: 0,
                        };
                        let _ = self.reading_streams.insert(token, reading_stream);
                    }
                },
            }
            return;
        }

        let mut done_read = false;
        if let hash_map::Entry::Occupied(mut oe) = self.reading_streams.entry(token) {
            let res = {
                let reading_stream = oe.get_mut();
                let read = reading_stream.bytes_read;
                reading_stream.stream.try_read(&mut reading_stream.in_buff[read..])
            };
            match res {
                Err(e) => {
                    debug!("Error reading stream during hole punching: {}", e);
                    let reading_stream = oe.remove();
                    match event_loop.deregister(&reading_stream.stream) {
                        Ok(()) => (),
                        Err(e) => debug!("Error deregistering socket: {}", e),
                    };
                    let _ = core.remove_context(token);
                    return;
                },
                Ok(None) => (),
                Ok(Some(0)) => {
                    let reading_stream = oe.remove();
                    let _ = core.remove_context(token);
                    match event_loop.deregister(&reading_stream.stream)
                    {
                        Ok(()) => (),
                        Err(e) => {
                            debug!("Error deregistering stream: {}", e);
                            return;
                        },
                    };
                },
                Ok(Some(n)) => {
                    oe.get_mut().bytes_read += n;
                    let read = oe.get_mut().bytes_read;
                    if read >= SECRET_LEN + NONCE_LEN {
                        let reading_stream = oe.remove();
                        let _ = core.remove_context(token);
                        match event_loop.deregister(&reading_stream.stream) {
                            Ok(()) => (),
                            Err(e) => {
                                debug!("Error deregistering socket: {}", e);
                                return;
                            },
                        };
                        let recv_secret = &reading_stream.in_buff[..SECRET_LEN];
                        if recv_secret != self.their_secret {
                            debug!("Secret mismatch during hole punching: {:?} != {:?}",
                                   recv_secret, self.their_secret);
                            return;
                        }
                        let recv_nonce = Cursor::new(&reading_stream.in_buff[SECRET_LEN..])
                                                .read_u64::<BigEndian>().unwrap();
                        let sent_nonce = Cursor::new(&reading_stream.nonce[..])
                                                .read_u64::<BigEndian>().unwrap();
                        let new_score = recv_nonce.wrapping_add(sent_nonce);
                        let old_score = self.best_stream.as_ref().map(|&(i, _)| i).unwrap_or(0);
                        if new_score >= old_score {
                            self.best_stream = Some((new_score, reading_stream.stream));
                        }
                        done_read = true;
                    }
                },
            }
        }

        if self.writing_streams.is_empty() && 
           self.reading_streams.is_empty() &&
           done_read
        {
            self.terminate(core, event_loop);
            return;
        }
    }

    fn terminate(&mut self,
                 core: &mut Core,
                 event_loop: &mut EventLoop<Core>)
    {
        let stream_opt = self.best_stream.take().map(|(_, s)| s);
        let finished = self.finished.take().unwrap();

        finished(core, event_loop, stream_opt);

        for (token, writing_stream) in self.writing_streams.iter() {
            match event_loop.deregister(&writing_stream.stream) {
                Ok(()) => (),
                Err(e) => debug!("Error deregistering stream: {}", e),
            };
            let _ = core.remove_context(*token);
        }

        for (token, reading_stream) in self.reading_streams.iter() {
            match event_loop.deregister(&reading_stream.stream) {
                Ok(()) => (),
                Err(e) => debug!("Error deregistering stream: {}", e),
            };
            let _ = core.remove_context(*token);
        }

        match event_loop.deregister(&self.listener) {
            Ok(()) => (),
            Err(e) => debug!("Error deregistering stream: {}", e),
        };
        let _ = core.remove_context(self.listener_token);

        let _ = core.remove_state(self.context);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

