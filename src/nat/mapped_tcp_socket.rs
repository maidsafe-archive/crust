//! Tcp socket mapping

use std::net::SocketAddr;
use std::io;
use std::collections::{HashMap, hash_map};
use std::cell::RefCell;
use std::rc::Rc;

use net2;
use mio::tcp::TcpStream;
use mio::{PollOpt, EventSet, Token, EventLoop};
use mio::{TryRead, TryWrite};
use socket_addr;

use core::Core;
use state::State;
use nat::util::new_reusably_bound_tcp_socket;
use maidsafe_utilities::serialisation::deserialise;

const REQUEST_MAGIC_CONSTANT: [u8; 4] = ['E' as u8, 'C' as u8, 'H' as u8, 'O' as u8];

struct WritingSocket {
    socket: TcpStream,
    written: usize,
}

struct ReadingSocket {
    socket: TcpStream,
    read_data: Vec<u8>,
}

/// A state which represents the in-progress mapping of a tcp socket.
pub struct MappingTcpSocket {
    socket: net2::TcpBuilder,
    writing_sockets: HashMap<Token, WritingSocket>,
    reading_sockets: HashMap<Token, ReadingSocket>,
    mapped_addrs: Vec<SocketAddr>,
}

impl MappingTcpSocket {
    pub fn new(core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               local_addr: &SocketAddr,
               server_addrs: &[SocketAddr]
            ) -> io::Result<()>
    {
        let context = core.get_new_context();

        let socket = try!(new_reusably_bound_tcp_socket(local_addr));

        let mut writing_sockets = HashMap::new();
        for server_addr in server_addrs {
            let query_socket = try!(new_reusably_bound_tcp_socket(local_addr));
            let query_socket = try!(query_socket.to_tcp_stream());
            let query_socket = try!(TcpStream::connect_stream(query_socket, server_addr));
            let token = core.get_new_token();
            try!(event_loop.register(&query_socket,
                                     token,
                                     EventSet::writable() | EventSet::error(),
                                     PollOpt::edge()
            ));
            let _ = core.insert_context(token, context.clone());
            let writing_socket = WritingSocket {
                socket: query_socket,
                written: 0usize,
            };
            writing_sockets.insert(token, writing_socket);
        }
        let _ = core.insert_state(context, Rc::new(RefCell::new(MappingTcpSocket {
            socket: socket,
            writing_sockets: writing_sockets,
            reading_sockets: HashMap::new(),
            mapped_addrs: Vec::new(),
        })));
        Ok(())
    }

    pub fn stop(self, event_loop: &mut EventLoop<Core>) -> (net2::TcpBuilder, Vec<SocketAddr>) {
        for writing_socket in self.writing_sockets.values() {
            let _ = event_loop.deregister(&writing_socket.socket);
        }

        for reading_socket in self.reading_sockets.values() {
            let _ = event_loop.deregister(&reading_socket.socket);
        }

        let socket = self.socket;
        let mapped_addrs = self.mapped_addrs;
        (socket, mapped_addrs)
    }
}

impl State for MappingTcpSocket {
    fn execute(&mut self,
               core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               token: Token,
               event_set: EventSet)
    {
        if event_set.is_error() {
            if let hash_map::Entry::Occupied(oe) = self.writing_sockets.entry(token) {
                let writing_socket = oe.remove();
                if let Err(e) = writing_socket.socket.take_socket_error() {
                    debug!("Error sending request to mapping server: {}", e);
                }
            }

            if let hash_map::Entry::Occupied(oe) = self.reading_sockets.entry(token) {
                let reading_socket = oe.remove();
                if let Err(e) = reading_socket.socket.take_socket_error() {
                    debug!("Error receiving request from mapping server: {}", e);
                }
            }
        }
        
        if event_set.is_writable() {
            if let hash_map::Entry::Occupied(mut oe) = self.writing_sockets.entry(token) {
                let res = {
                    let writing_socket = oe.get_mut();
                    writing_socket.socket.try_write(&REQUEST_MAGIC_CONSTANT[writing_socket.written..])
                };
                match res {
                    Err(e) => {
                        debug!("Error writing to socket: {}", e);
                        let _ = oe.remove();
                    },
                    Ok(None) => return,
                    Ok(Some(n)) => {
                        oe.get_mut().written += n;
                        if oe.get_mut().written >= REQUEST_MAGIC_CONSTANT.len() {
                            let writing_socket = oe.remove();
                            match event_loop.reregister(&writing_socket.socket,
                                                  token,
                                                  EventSet::readable() | EventSet::error(),
                                                  PollOpt::edge()
                            ) {
                                Ok(()) => (),
                                Err(e) => {
                                    debug!("Error registering with event loop: {}", e);
                                    return;
                                },
                            };
                            let reading_socket = ReadingSocket {
                                socket: writing_socket.socket,
                                read_data: Vec::new(),
                            };
                            self.reading_sockets.insert(token, reading_socket);
                        }
                    },
                }
            }
        }

        if event_set.is_readable() {
            const MAX_RECV_MSG_SIZE: usize = 256usize;

            if let hash_map::Entry::Occupied(mut oe) = self.reading_sockets.entry(token) {
                let mut buf = [0u8; 256];
                let res = {
                    let reading_socket = oe.get_mut();
                    reading_socket.socket.try_read(&mut buf[..])
                };
                match res {
                    Err(e) => {
                        debug!("Error writing to socket: {}", e);
                        let _ = oe.remove();
                    },
                    Ok(None) => return,
                    Ok(Some(n)) => {
                        if n == 0 {
                            let reading_socket = oe.remove();
                            match event_loop.deregister(&reading_socket.socket) {
                                Ok(()) => (),
                                Err(e) => {
                                    debug!("Error deregistering with event loop: {}", e);
                                    return;
                                },
                            };
                            let response: socket_addr::SocketAddr = match deserialise(&reading_socket.read_data[..]) {
                                Ok(response) => response,
                                Err(e) => {
                                    debug!("Error deserialising response from mapping server: {}", e);
                                    return;
                                },
                            };
                            self.mapped_addrs.push(response.0);
                        }
                        else {
                            oe.get_mut().read_data.extend(&buf[..n]);
                        }
                    },
                }
            }
        }
    }
}

