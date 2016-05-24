//! Tcp socket mapping

use std::net::SocketAddr;
use std::io;
use std::collections::{HashMap, hash_map};
use std::mem;
use std::any::Any;

use net2;
use mio::tcp::TcpStream;
use mio::{PollOpt, EventSet, Token, EventLoop};
use mio::{TryRead, TryWrite};
use socket_addr;
use maidsafe_utilities::serialisation::deserialise;

use core::{Core, Context};
use core::state::State;
use nat::util::{new_reusably_bound_tcp_socket, tcp_builder_local_addr, expand_unspecified_addr};
use nat::mapping_context::MappingContext;

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
pub struct MappingTcpSocket<F> {
    socket: Option<net2::TcpBuilder>,
    writing_sockets: HashMap<Token, WritingSocket>,
    reading_sockets: HashMap<Token, ReadingSocket>,
    mapped_addrs: Vec<socket_addr::SocketAddr>,
    external_addrs: u32,
    finished: Option<F>,
    context: Context,
}

impl<F> MappingTcpSocket<F>
        where F: FnOnce(&mut Core, &mut EventLoop<Core>, net2::TcpBuilder, Vec<socket_addr::SocketAddr>) + Any
{
    /// Start mapping a tcp socket
    pub fn new(core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               local_addr: &SocketAddr,
               mapping_context: &MappingContext,
               finished: F,
            ) -> io::Result<()>
    {
        debug!("MappingTcpSocket::new()");
        let context = core.get_new_context();

        let socket = try!(new_reusably_bound_tcp_socket(local_addr));
        let local_addr = try!(tcp_builder_local_addr(&socket));
        let mapped_addrs = try!(expand_unspecified_addr(local_addr));
        let mapped_addrs = mapped_addrs.into_iter().map(|sa| socket_addr::SocketAddr(sa)).collect();
        
        let external_servers: Vec<SocketAddr> = mapping_context.tcp_mapping_servers()
                                                               .cloned()
                                                               .collect();
        debug!("external_servers == {:?}", external_servers);
        if external_servers.len() > 0 {
            let mut writing_sockets = HashMap::new();
            for server_addr in mapping_context.tcp_mapping_servers() {
                let query_socket = try!(new_reusably_bound_tcp_socket(&local_addr));
                let query_socket = try!(query_socket.to_tcp_stream());
                let query_socket = try!(TcpStream::connect_stream(query_socket, server_addr));
                let token = core.get_new_token();
                try!(event_loop.register(&query_socket,
                                         token,
                                         EventSet::writable() | EventSet::error() | EventSet::hup(),
                                         PollOpt::edge()
                ));
                let _ = core.insert_context(token, context.clone());
                let writing_socket = WritingSocket {
                    socket: query_socket,
                    written: 0usize,
                };
                let _ = writing_sockets.insert(token, writing_socket);
            }
            let _ = core.insert_state(context.clone(), MappingTcpSocket {
                socket: Some(socket),
                writing_sockets: writing_sockets,
                reading_sockets: HashMap::new(),
                mapped_addrs: mapped_addrs,
                external_addrs: 0,
                finished: Some(finished),
                context: context,
            });
        }
        else {
            finished(core, event_loop, socket, mapped_addrs);
        }
        Ok(())
    }

    fn stop(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) -> (net2::TcpBuilder, Vec<socket_addr::SocketAddr>) {
        for (token, writing_socket) in self.writing_sockets.iter() {
            match event_loop.deregister(&writing_socket.socket) {
                Ok(()) => (),
                Err(e) => debug!("Error deregistering socket: {}", e),
            };
            let _ = core.remove_context(*token);
        }

        for (token, reading_socket) in self.reading_sockets.iter() {
            match event_loop.deregister(&reading_socket.socket) {
                Ok(()) => (),
                Err(e) => debug!("Error deregistering socket: {}", e),
            };
            let _ = core.remove_context(*token);
        }

        let _ = core.remove_state(self.context);

        let socket = self.socket.take().unwrap();
        let mapped_addrs = mem::replace(&mut self.mapped_addrs, Vec::new());
        (socket, mapped_addrs)
    }
    
    fn process(&mut self, core: &mut Core,
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
                let _ = core.remove_context(token);
                match event_loop.deregister(&writing_socket.socket) {
                    Ok(()) => (),
                    Err(e) => debug!("Error deregistering socket: {}", e),
                }
            }

            if let hash_map::Entry::Occupied(oe) = self.reading_sockets.entry(token) {
                let reading_socket = oe.remove();
                if let Err(e) = reading_socket.socket.take_socket_error() {
                    debug!("Error receiving request from mapping server: {}", e);
                }
                let _ = core.remove_context(token);
                match event_loop.deregister(&reading_socket.socket) {
                    Ok(()) => (),
                    Err(e) => debug!("Error deregistering socket: {}", e),
                };
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
                    Ok(None) => (),
                    Ok(Some(n)) => {
                        oe.get_mut().written += n;
                        if oe.get_mut().written >= REQUEST_MAGIC_CONSTANT.len() {
                            let writing_socket = oe.remove();
                            match event_loop.reregister(&writing_socket.socket,
                                                  token,
                                                  EventSet::readable() | EventSet::error() | EventSet::hup(),
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
                            let _ = self.reading_sockets.insert(token, reading_socket);
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
                    Ok(None) => (),
                    Ok(Some(n)) => {
                        if n == 0 {
                            let reading_socket = oe.remove();
                            let _ = core.remove_context(token);
                            match event_loop.deregister(&reading_socket.socket) {
                                Ok(()) => (),
                                Err(e) => debug!("Error deregistering with event loop: {}", e),
                            };
                            let response: socket_addr::SocketAddr = match deserialise(&reading_socket.read_data[..]) {
                                Ok(response) => response,
                                Err(e) => {
                                    debug!("Error deserialising response from mapping server: {}", e);
                                    return;
                                },
                            };
                            if !self.mapped_addrs.contains(&response) {
                                self.mapped_addrs.push(response);
                                self.external_addrs += 1;
                            }
                        }
                        else {
                            oe.get_mut().read_data.extend(&buf[..n]);
                            let len = oe.get_mut().read_data.len();
                            if len > MAX_RECV_MSG_SIZE {
                                debug!("Overly long response from mapping server: {} bytes", len);
                                let reading_socket = oe.remove();
                                let _ = core.remove_context(token);
                                match event_loop.deregister(&reading_socket.socket) {
                                    Ok(()) => (),
                                    Err(e) => debug!("Error deregistering socket: {}", e),
                                }
                            }
                        }
                    },
                }
            }
        }
    }
}

impl<F> State for MappingTcpSocket<F>
        where F: FnOnce(&mut Core, &mut EventLoop<Core>, net2::TcpBuilder, Vec<socket_addr::SocketAddr>) + Any
{
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet)
    {
        println!("MappingTcpSocket::execute()");
        self.process(core, event_loop, token, event_set);

        if self.external_addrs >= 2 || (self.writing_sockets.is_empty() &&
                                        self.reading_sockets.is_empty()) {
            let (socket, addrs) = self.stop(core, event_loop);
            let finished = self.finished.take().unwrap();
            finished(core, event_loop, socket, addrs);
        }
    }

    fn terminate(&mut self,
                 core: &mut Core,
                 event_loop: &mut EventLoop<Core>)
    {
        let _ = self.stop(core, event_loop);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

