//! Implements the tcp socket mapping server

use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::collections::{HashMap, hash_map};
use std::cell::RefCell;
use std::rc::Rc;
use std::io;

use mio::tcp::{TcpListener, TcpStream};
use mio::{PollOpt, EventSet, Token, EventLoop};
use mio::{TryRead, TryWrite};
use socket_addr;
use maidsafe_utilities::serialisation::serialise;

use core::{Core, Context};
use state::State;
use nat::mapping_context::MappingContext;
use nat::mapped_tcp_socket::MappingTcpSocket;

/// A tcp socket mapping server
pub struct TcpMappingServer {
    server_socket: TcpListener,
    reading_clients: HashMap<Token, ReadingClient>,
    writing_clients: HashMap<Token, WritingClient>,
    server_token: Token,
    context: Context,
}

struct ReadingClient {
    stream: TcpStream,
    in_buffer: [u8; 4],
    bytes_read: usize,
    their_addr: SocketAddr,
}

struct WritingClient {
    stream: TcpStream,
    out_buffer: Vec<u8>,
    bytes_written: usize,
}

impl TcpMappingServer {
    /// Register a new tcp socket mapping server with the event loop
    pub fn new<F>(core: &mut Core,
                  event_loop: &mut EventLoop<Core>,
                  mapping_context: &MappingContext,
                  report_addresses: F) -> io::Result<()>
        where F: FnOnce(&mut Core, &mut EventLoop<Core>, io::Result<Vec<socket_addr::SocketAddr>>) + 'static
    {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
        MappingTcpSocket::new(core, event_loop, &addr, mapping_context, |core, event_loop, socket, addrs| {
            let res = {
                let try = || {
                    let context = core.get_new_context();
                    let token = core.get_new_token();
                    let listener = try!(socket.listen(1));
                    let addr = try!(listener.local_addr());
                    let listener = try!(TcpListener::from_listener(listener, &addr));
                    try!(event_loop.register(&listener,
                                             token,
                                             EventSet::readable() | EventSet::error() | EventSet::hup(),
                                             PollOpt::edge(),
                    ));
                    let _ = core.insert_context(token, context.clone());
                    let _ = core.insert_state(context.clone(), Rc::new(RefCell::new(TcpMappingServer {
                        server_socket: listener,
                        reading_clients: HashMap::new(),
                        writing_clients: HashMap::new(),
                        server_token: token,
                        context: context,
                    })));
                    Ok(addrs)
                };
                try()
            };
            report_addresses(core, event_loop, res);
        })
    }
}

impl State for TcpMappingServer {
    fn execute(&mut self,
               core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               token: Token,
               _event_set: EventSet)
    {
        if token == self.server_token {
            let (client, their_addr) = match self.server_socket.accept() {
                Err(e) => {
                    debug!("Error accepting tcp mapper client: {}", e);
                    //self.stop(core, event_loop);
                    return;
                },
                Ok(None) => return,
                Ok(Some(client)) => client,
            };

            let token = core.get_new_token();
            let _ = core.insert_context(token, self.context.clone());
            match event_loop.register(&client,
                                      token,
                                      EventSet::readable() | EventSet::error() | EventSet::hup(),
                                      PollOpt::edge())
            {
                Ok(()) => (),
                Err(e) => {
                    debug!("Error registering socket: {}", e);
                    return;
                },
            }
            let client = ReadingClient {
                stream: client,
                in_buffer: [0u8; 4],
                bytes_read: 0,
                their_addr: their_addr,
            };
            let _ = self.reading_clients.insert(token, client);
        }

        if let hash_map::Entry::Occupied(mut oe) = self.reading_clients.entry(token) {
            let res = {
                let reading_client = oe.get_mut();
                reading_client.stream.try_read(&mut reading_client.in_buffer[reading_client.bytes_read..])
            };
            match res {
                Err(e) => {
                    debug!("Error reading from mapping client: {}", e);
                    let reading_client = oe.remove();
                    match event_loop.deregister(&reading_client.stream) {
                        Ok(()) => (),
                        Err(e) => debug!("Error deregistering socket: {}", e),
                    };
                    let _ = core.remove_context(&token);
                },
                Ok(None) => return,
                Ok(Some(n)) => {
                    oe.get_mut().bytes_read += n;
                    let total = oe.get_mut().bytes_read;
                    if total >= oe.get_mut().in_buffer.len() {
                        let reading_client = oe.remove();
                        if &reading_client.in_buffer[..] != b"ECHO" {
                            debug!("Invalid request from mapping client: {:?}", &reading_client.in_buffer[..]);
                            match event_loop.deregister(&reading_client.stream) {
                                Ok(()) => (),
                                Err(e) => debug!("Error deregistering socket: {}", e),
                            };
                            let _ = core.remove_context(&token);
                        }
                        match event_loop.reregister(&reading_client.stream,
                                              token,
                                              EventSet::writable() | EventSet::writable() | EventSet::hup(),
                                              PollOpt::edge())
                        {
                            Ok(()) => (),
                            Err(e) => {
                                debug!("Error registering socket: {}", e);
                                let _ = core.remove_context(&token);
                            },
                        }
                        let their_addr = serialise(&socket_addr::SocketAddr(reading_client.their_addr)).unwrap();
                        let writing_client = WritingClient {
                            stream: reading_client.stream,
                            out_buffer: their_addr,
                            bytes_written: 0usize,
                        };
                        let _ = self.writing_clients.insert(token, writing_client);
                    }
                },
            }
            return;
        }

        if let hash_map::Entry::Occupied(mut oe) = self.writing_clients.entry(token) {
            let res = {
                let writing_client = oe.get_mut();
                writing_client.stream.try_write(&writing_client.out_buffer[writing_client.bytes_written..])
            };
            match res {
                Err(e) => {
                    debug!("Error writing to mapping client: {}", e);
                    let writing_client = oe.remove();
                    match event_loop.deregister(&writing_client.stream) {
                        Ok(()) => (),
                        Err(e) => debug!("Error deregistering socket: {}", e),
                    };
                    let _ = core.remove_context(&token);
                },
                Ok(None) => return,
                Ok(Some(n)) => {
                    oe.get_mut().bytes_written += n;
                    let total = oe.get_mut().bytes_written;
                    if total >= oe.get_mut().out_buffer.len() {
                        let writing_client = oe.remove();
                        match event_loop.deregister(&writing_client.stream) {
                            Ok(()) => (),
                            Err(e) => debug!("Error deregistering socket: {}", e),
                        };
                        let _ = core.remove_context(&token);
                    }
                },
            }
            return;
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        match event_loop.deregister(&self.server_socket) {
            Ok(()) => (),
            Err(e) => debug!("Error deregistering socket: {}", e),
        };
        let _ = core.remove_context(&self.server_token);

        for (token, reading_client) in self.reading_clients.iter() {
            match event_loop.deregister(&reading_client.stream) {
                Ok(()) => (),
                Err(e) => debug!("Error deregistering socket: {}", e),
            };
            let _ = core.remove_context(&token);
        }

        for (token, writing_client) in self.writing_clients.iter() {
            match event_loop.deregister(&writing_client.stream) {
                Ok(()) => (),
                Err(e) => debug!("Error deregistering socket: {}", e),
            };
            let _ = core.remove_context(&token);
        }

        let _ = core.remove_state(&self.context);
    }
}

