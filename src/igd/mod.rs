use std::rc::Rc;
use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::io;
use std::str;
use std::any::Any;
use mio::{PollOpt, Token, EventLoop, EventSet};
use mio::udp;
use http_pull_parser::{Parser, ParserError, HttpToken};
use core::{Core, Context, State};

mod errors;
mod gateway;
mod http_request;
mod utils;

pub use igd::gateway::Gateway;
pub use igd::errors::{SearchError, GetExternalIpError, AddAnyPortError};
use igd::utils::{get_control_url, parse_result};

// Content of the request.
const SEARCH_REQUEST: &'static str =
"M-SEARCH * HTTP/1.1\r
Host:239.255.255.250:1900\r
ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r
Man:\"ssdp:discover\"\r
MX:3\r\n\r\n";

struct Closure(Box<FnMut(&mut Core, &mut EventLoop<Core>)>);

impl Closure {
    pub fn new<F>(f: F) -> Closure
        where F: FnOnce(&mut Core, &mut EventLoop<Core>) + 'static {
        let mut f = Some(f);
        Closure(Box::new(move |core, event_loop| {
            if let Some(f) = f.take() {
                f(core, event_loop)
            }
        }))
    }

    pub fn invoke(&mut self, core: &mut Core,
                  event_loop: &mut EventLoop<Core>) {
        (self.0)(core, event_loop)
    }
}

struct Closure2(Box<FnMut(Result<Gateway, SearchError>, &mut Core,
                          &mut EventLoop<Core>)>);

impl Closure2 {
    pub fn new<F>(f: F) -> Closure2
        where F: FnOnce(Result<Gateway, SearchError>, &mut Core,
                        &mut EventLoop<Core>) + 'static {
        let mut f = Some(f);
        Closure2(Box::new(move |res, core, event_loop| {
            if let Some(f) = f.take() {
                f(res, core, event_loop)
            }
        }))
    }

    pub fn empty() -> Closure2 {
        Closure2(Box::new(|_, _, _| ()))
    }

    pub fn invoke(&mut self, res: Result<Gateway, SearchError>, core: &mut Core,
                  event_loop: &mut EventLoop<Core>) {
        (self.0)(res, core, event_loop)
    }
}

pub struct SearchGateway {
    context: Context,
    callback: Closure2,
    socket: udp::UdpSocket,
}

impl SearchGateway {
    pub fn search<F>(core: &mut Core,
                     event_loop: &mut EventLoop<Core>,
                     callback: F)
        where F: FnOnce(Result<Gateway, SearchError>, &mut Core,
                        &mut EventLoop<Core>) + 'static {
        Self::search_from(core, event_loop, "0.0.0.0".parse().unwrap(),
                          callback);
    }

    pub fn search_from<F>(core: &mut Core,
                          event_loop: &mut EventLoop<Core>,
                          ip: Ipv4Addr,
                          callback: F)
        where F: FnOnce(Result<Gateway, SearchError>, &mut Core,
                        &mut EventLoop<Core>) + 'static {
        let context = core.get_new_context();
        let token = core.get_new_token();
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, 0));
        let socket = udp::UdpSocket::bound(&addr).unwrap();

        if let Err(e) = socket.send_to(SEARCH_REQUEST.as_bytes(),
                                       &"239.255.255.250:1900".parse().unwrap()) {
            callback(Err(SearchError::IoError(e)), core, event_loop);
            return;
        }

        if let Err(e) = event_loop.register(&socket, token,
                                            EventSet::error()
                                            | EventSet::readable(),
                                            PollOpt::edge()) {
            error!("Could not register socket with EventLoop<Code>: {:?}", e);
            // TODO(?): call callback?
            return;
        }

        let _ = core.insert_context(token, context);

        let state = SearchGateway {
            context: context.clone(),
            callback: Closure2::new(callback),
            socket: socket,
        };

        let _ = core.insert_state(context, state);
    }

    fn take_callback(&mut self) -> Closure2 {
        use std::mem;
        let mut t = Closure2::empty();
        mem::swap(&mut t, &mut self.callback);
        t
    }
}

impl State for SearchGateway {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet) {
        use std::io;
        use std::io::Write;
        let mut buf = [0u8; 1024];
        let res = self.socket.recv_from(&mut buf);
        match res {
            Ok(Some((read, _))) => {
                let text = match str::from_utf8(&buf[..read]) {
                    Ok(t) => t,
                    Err(e) => {
                        self.callback.invoke(Err(SearchError::Utf8Error(e)),
                                             core, event_loop);
                        return;
                    }
                };
                match parse_result(text) {
                    None => {
                        self.callback.invoke(Err(SearchError::InvalidResponse),
                                             core, event_loop);
                        return;
                    }
                    Some(location) => {
                        let mut cb2 = self.take_callback();
                        let location2 = location.0.clone();
                        get_control_url(&location, core, event_loop,
                                        move |res, core, event_loop| {
                                            let control_url = match res {
                                                Ok(v) => v,
                                                Err(e) => {
                                                    cb2.invoke(Err(e), core,
                                                               event_loop);
                                                    return;
                                                }
                                            };
                                            let gateway = Gateway {
                                                addr: location2,
                                                control_url: control_url,
                                            };
                                            cb2.invoke(Ok(gateway), core,
                                                       event_loop);
                                            return;
                                        });
                        return;
                    },
                }
            }
            Ok(None) => {
                if let Err(e) = event_loop.register(&self.socket, token,
                                                    EventSet::error()
                                                    | EventSet::readable(),
                                                    PollOpt::edge()) {
                    error!("Could not register socket with EventLoop<Code>: {:?}",
                           e);
                    // TODO(?): call callback
                    return;
                }
            }
            Err(e) => {
                self.callback.invoke(Err(SearchError::IoError(e)), core,
                                     event_loop);
                return;
            }
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

pub struct GetExternalIp {
    context: Context,
    callback: Closure,
    //socket: tcp::TcpStream,
}

impl GetExternalIp {
    //pub fn new<F>(core: &mut Core,
    //              event_loop: &mut EventLoop<Core>,
    //              callback: F)
    //    where F: FnOnce() + 'static {
    //    println!("YYY");
    //    let context = core.get_new_context();
    //    let token = core.get_new_token();
    //    let addr = "127.0.0.1:8080".parse().unwrap();
    //    let stream = tcp::TcpStream::connect(&addr).unwrap();
    //
    //    if let Err(e) = event_loop.register(&stream, token,
    //                                        EventSet::error() | EventSet::writable(),
    //                                        PollOpt::edge()) {
    //        error!("Could not register socket with EventLoop<Code>: {:?}", e);
    //        return;
    //    }
    //
    //    let _ = core.insert_context(token, context);
    //
    //    let state = GetExternalIp {
    //        context: context.clone(),
    //        callback: Closure::new(callback),
    //        stream: stream,
    //    };
    //
    //    let _ = core.insert_state(context, state);
    //}
}

impl State for GetExternalIp {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet) {
        use std::io;
        use std::io::Write;
        println!("XXX");
        let _ = io::stdout().flush();
        self.callback.invoke(core, event_loop);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

pub struct AddAnyPort {
    context: Context,
    callback: Closure,
    //stream: tcp::TcpStream,
}

impl AddAnyPort {
    //pub fn new<F>(core: &mut Core,
    //              event_loop: &mut EventLoop<Core>,
    //              callback: F)
    //    where F: FnOnce() + 'static {
    //    println!("YYY");
    //    let context = core.get_new_context();
    //    let token = core.get_new_token();
    //    let addr = "127.0.0.1:8080".parse().unwrap();
    //    let stream = tcp::TcpStream::connect(&addr).unwrap();
    //
    //    if let Err(e) = event_loop.register(&stream, token,
    //                                        EventSet::error() | EventSet::writable(),
    //                                        PollOpt::edge()) {
    //        error!("Could not register socket with EventLoop<Code>: {:?}", e);
    //        return;
    //    }
    //
    //    let _ = core.insert_context(token, context);
    //
    //    let state = AddAnyPort {
    //        context: context.clone(),
    //        callback: Closure::new(callback),
    //        stream: stream,
    //    };
    //
    //    let _ = core.insert_state(context, state);
    //}
}

impl State for AddAnyPort {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet) {
        use std::io;
        use std::io::Write;
        println!("XXX");
        let _ = io::stdout().flush();
        self.callback.invoke(core, event_loop);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use core::Core;
    use mio::EventLoop;
    use super::*;

    #[test]
    fn foobar() {
        let mut event_loop = EventLoop::new().unwrap();
        let mut core = Core::new();
        SearchGateway::search(&mut core, &mut event_loop,
                              |res, core, event_loop| {
                                  println!("Hello World {:?}", res.and(Ok(42)));
                              });
        event_loop.run(&mut core).expect("EventLoop failed to run");
    }
}
