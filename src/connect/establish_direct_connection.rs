use std::io;
use std::net::SocketAddr;
use std::any::Any;
use std::rc::Rc;
use std::cell::RefCell;

use mio::tcp::TcpStream;
use mio::{EventSet, PollOpt, Token, EventLoop};

use core::{Core, Context, State};
use peer_id::PeerId;

pub struct EstablishDirectConnection<F> {
    stream: Option<TcpStream>,
    finish: Option<F>,
    token: Token,
    context: Context,
    peer_id: PeerId,
}

impl<F> EstablishDirectConnection<F>
    where F: FnOnce(&mut Core,
                    &mut EventLoop<Core>,
                    io::Result<(Token, TcpStream)>,
                    PeerId) + Any
{
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 addr: SocketAddr,
                 peer_id: PeerId,
                 finish: F)
                 -> io::Result<()> {
        let token = core.get_new_token();
        let context = core.get_new_context();

        let stream = try!(TcpStream::connect(&addr));
        try!(event_loop.register(&stream,
                                 token,
                                 EventSet::writable() | EventSet::error(),
                                 PollOpt::edge()));
        let state = EstablishDirectConnection {
            stream: Some(stream),
            finish: Some(finish),
            token: token,
            context: context,
            peer_id: peer_id,
        };

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));
        Ok(())
    }
}

impl<F> State for EstablishDirectConnection<F>
    where F: FnOnce(&mut Core,
                    &mut EventLoop<Core>,
                    io::Result<(Token, TcpStream)>,
                    PeerId) + Any
{
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet) {
        if event_set.is_error() {
            let _ = core.remove_state(self.context);
            let _ = core.remove_context(self.token);
            let finish = self.finish.take().unwrap();
            let stream = self.stream.take().unwrap();
            match event_loop.deregister(&stream) {
                Ok(()) => (),
                Err(e) => debug!("Error deregistering stream: {}", e),
            };
            let error = match stream.take_socket_error() {
                Ok(()) => io::Error::new(io::ErrorKind::Other, "Unknown error"),
                Err(e) => e,
            };
            finish(core, event_loop, Err(error), self.peer_id);
        } else if event_set.is_writable() {
            let _ = core.remove_state(self.context);
            let finish = self.finish.take().unwrap();
            let stream = self.stream.take().unwrap();
            finish(core, event_loop, Ok((self.token, stream)), self.peer_id);
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let _ = core.remove_state(self.context);
        let _ = core.remove_context(self.token);
        let stream = self.stream.take().unwrap();
        match event_loop.deregister(&stream) {
            Ok(()) => (),
            Err(e) => debug!("Error deregistering stream: {}", e),
        };
        let finish = self.finish.take().unwrap();
        let error = io::Error::new(io::ErrorKind::Other, "Connect cancelled");
        finish(core, event_loop, Err(error), self.peer_id);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
