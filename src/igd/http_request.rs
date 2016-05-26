use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::io;
use std::io::{Read, Write};
use std::any::Any;
use http_pull_parser::{Parser, ParserError, HttpToken};
use mio::{EventSet, EventLoop, PollOpt, Token};
use mio::tcp;
use core::{Context, Core, State};
use igd::errors::HttpError;

struct Closure(Box<FnMut(Result<Vec<HttpToken>, HttpError>, &mut Core,
                         &mut EventLoop<Core>)>);

impl Closure {
    pub fn new<F>(f: F) -> Closure
        where F: FnOnce(Result<Vec<HttpToken>, HttpError>, &mut Core,
                        &mut EventLoop<Core>) + 'static {
        let mut f = Some(f);
        Closure(Box::new(move |res, core, event_loop| {
            if let Some(f) = f.take() {
                f(res, core, event_loop)
            }
        }))
    }

    pub fn invoke(&mut self, res: Result<Vec<HttpToken>, HttpError>,
                  core: &mut Core, event_loop: &mut EventLoop<Core>) {
        (self.0)(res, core, event_loop)
    }
}

enum MyState {
    Connecting { req_to_send: Vec<u8> },
    Receiving,
}

struct HttpRequest {
    context: Context,
    callback: Closure,
    socket: tcp::TcpStream,
    state: MyState,
    parser: Parser,
    buffer: Vec<u8>,
    result: Vec<HttpToken>,
}

impl HttpRequest {
    pub fn start<F>(core: &mut Core, event_loop: &mut EventLoop<Core>,
                    address: &SocketAddrV4, request: Vec<u8>, callback: F)
        where F: FnOnce(Result<Vec<HttpToken>, HttpError>, &mut Core,
                        &mut EventLoop<Core>) + 'static {
        let context = core.get_new_context();
        let token = core.get_new_token();
        let socket = tcp::TcpStream::connect(&SocketAddr::V4(address.clone()))
            .unwrap();

        if let Err(e) = event_loop.register(&socket, token,
                                            EventSet::error()
                                            | EventSet::readable(),
                                            PollOpt::edge()) {
            error!("Could not register socket with EventLoop<Code>: {:?}", e);
            // TODO(?): call callback?
            return;
        }

        let _ = core.insert_context(token, context);

        let state = HttpRequest {
            context: context.clone(),
            callback: Closure::new(callback),
            socket: socket,
            state: MyState::Connecting { req_to_send: request },
            parser: Parser::response(),
            buffer: Vec::new(),
            result: Vec::new(),
        };

        let _ = core.insert_state(context, state);
    }
}

impl State for HttpRequest {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet) {
        println!("{:?} {:?}", token, event_set);
        if !event_set.is_readable()
            || (event_set.is_readable() && event_set.is_hup()) {
            if let Err(e) = self.socket.take_socket_error() {
                self.callback.invoke(Err(HttpError::IoError(e)), core,
                                     event_loop);
                return;
            }
        }

        let mut new_state = None;
        match self.state {
            MyState::Connecting { ref req_to_send } => {
                self.socket.write_all(&req_to_send[..]).unwrap();
                new_state = Some(MyState::Receiving);

                if let Err(e) = event_loop.reregister(&self.socket, token,
                                                      EventSet::error()
                                                      | EventSet::readable()
                                                      | EventSet::hup(),
                                                      PollOpt::edge()) {
                    error!("Could not register socket with EventLoop<Code>: {:?}", e);
                    // TODO(?): call callback?
                    return;
                }
            }
            MyState::Receiving => {
                println!("I want to conquer the world");
                loop {
                    if !event_set.is_readable() {
                        break;
                    }

                    let mut buf = [0u8; 10240];
                    let read = self.socket.read(&mut buf).unwrap();
                    //println!("{:?}", socket.take_socket_error());
                    if read == 0 {
                        println!("{:?}", self.result);
                        break;
                    }
                    println!("{}", read);
                    let buf = &buf[..read];
                    self.buffer.extend(buf.into_iter());
                    loop {
                        let (res, nparsed)
                            = self.parser.next_token(Some(&self.buffer));
                        let _ = self.buffer.drain(..nparsed);
                        match res {
                            Ok(Some(t)) => {
                                self.result.push(t);

                                if *self.result.last().unwrap() == HttpToken::EndOfMessage {
                                    let res = self.result.drain(..).collect();
                                    self.callback.invoke(Ok(res), core,
                                                         event_loop);
                                    return;
                                }
                            }
                            Ok(none) => break,
                            Err(e) => {
                                self.callback.invoke(Err(HttpError::ParsingError(e)),
                                                     core, event_loop);
                                return;
                            }
                        }
                    }
                }
            }
        }
        if let Some(state) = new_state {
            self.state = state;
        }
        //if let Err(e) = event_loop.reregister(&self.socket, token,
        //                                      EventSet::error()
        //                                      | EventSet::readable()
        //                                      | EventSet::hup(),
        //                                      PollOpt::edge()) {
        //    error!("Could not register socket with EventLoop<Code>: {:?}", e);
        //    // TODO(?): call callback?
        //    return;
        //}
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

pub fn get<F>(address: &SocketAddrV4, path: &String, core: &mut Core,
              event_loop: &mut EventLoop<Core>, f: F)
    where F: FnOnce(Result<Vec<HttpToken>, HttpError>, &mut Core,
                    &mut EventLoop<Core>) + 'static {
    let req = format!("GET {} HTTP/1.0\r\n\r\n", path).into_bytes();
    HttpRequest::start(core, event_loop, address, req, f);
}
