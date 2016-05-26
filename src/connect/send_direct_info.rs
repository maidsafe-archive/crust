use std::io;
use std::any::Any;

use mio::tcp::TcpStream;
use mio::{Token, EventSet, PollOpt, EventLoop};
use mio::TryWrite;
use maidsafe_utilities::serialisation::serialise_into;

use core::{State, Core, Context};
use peer_id::PeerId;

struct SendDirectInfo<F> {
    stream: Option<TcpStream>,
    out_buff: Vec<u8>,
    bytes_written: usize,
    finish: Option<F>,
    peer_id: PeerId,
}

impl<F> SendDirectInfo<F>
        where F: FnOnce(&mut Core, &mut EventLoop<Core>, io::Result<(Token, Context, TcpStream)>, PeerId) + Any
{
    fn start(core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             context: Context,
             stream: TcpStream,
             peer_id: PeerId,
             finish: F)
    {
        let mut out_buff = Vec::new();
        serialise_into(&peer_id, &mut out_buff);

        let bytes_written = match stream.try_write(&out_buff[..]) {
            Ok(Some(n)) => {
                if n == out_buff.len() {
                    finish(core, event_loop, Ok(token, context, stream), peer_id);
                    return;
                }
                else {
                    n
                }
            },
            Ok(None) => {
                0
            },
            Err(e) => {
                finish(core, event_loop, Err(e), peer_id);
                return;
            },
        };

        let state = SendDirectInfo {
            stream: stream,
            out_buff: out_buff,
            bytes_written: bytes_written,
            finish: finish,
        };

        let _ = core.insert_state(context, state);
    }
}

impl<F> State for SendDirectInfo<F>
        where F: FnOnce(&mut Core, &mut EventLoop<Core>, io::Result<(Token, Context, TcpStream)>, PeerId) + Any
{
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet)
    {
        if event_set.is_error() {
            let _ = core.remove_state(self.context);
            let _ = core.remove_context(token);

            let finish = self.finish.take().unwrap();
            let stream = self.stream.take().unwrap();
            match event_loop.deregister(&self.stream) {
                Ok(()) => (),
                Err(e) => debug!("Error deregistering stream: {}", e),
            };
            let error = match stream.take_socket_error() {
                Ok(()) => io::Error::new(io::ErrorKind::Other, "Unknown error"),
                Err(e) => e,
            };
            finish(core, event_loop, Err(error), self.peer_id);
        }
        else if event_set.is_writable() {
            let res = {
                let stream = self.stream.as_ref().unwrap();
                stream.try_write(&self.out_buff[self.bytes_written..]);
            };
            let bytes_written = match res {
                Ok(Some(n)) => {
                    if self.bytes_written + n == self.out_buff.len() {
                        let _ = core.remove_state(self.context);
                        let stream = self.stream.take().unwrap();
                        let finish = self.finish.take().unwrap();
                        finish(core, event_loop, Ok((self.token, self.context, stream)), self.peer_id);
                        return;
                    }
                    else {
                        n
                    }
                },
                Ok(None) => {
                    0
                },
                Err(e) => {
                    let _ = core.remove_state(self.context);
                    let _ = core.remove_context(self.token);
                    match event_loop.deregister(&self.stream) {
                        Ok(()) => (),
                        Err(e) => debug!("Error deregistering stream: {}", e),
                    };
                    let finish = self.finish.take().unwrap();
                    finish(core, event_loop, Err(e), self.peer_id);
                    return;
                },
            };
            self.bytes_written += bytes_written;
        }
        else if event_set.is_hup() {
            let _ = core.remove_state(self.context);
            let _ = core.remove_context(token);

            let finish = self.finish.take().unwrap();
            let stream = self.stream.take().unwrap();
            match event_loop.deregister(&self.stream) {
                Ok(()) => (),
                Err(e) => debug!("Error deregistering stream: {}", e),
            };
            let error = io::Error::new(io::ErrorKind::Other, "Remote disconnected");
            finish(core, event_loop, Err(error), self.peer_id);
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}


