use std::io;
use std::net::SocketAddr;
use std::any::Any;
use std::rc::Rc;
use std::cell::RefCell;

use mio::{EventSet, PollOpt, Token, EventLoop};

use core::{Core, Context, State};
use peer_id::PeerId;
use socket::{Socket, SocketError};

pub struct EstablishDirectConnection<F> {
    socket: Option<Socket>,
    finish: Option<F>,
    token: Token,
    context: Context,
    peer_id: PeerId,
    our_public_key: PublicKey,
    name_hash: u64,
    handshake_send: HandshakeState,
    handshake_receive: HandshakeState,
}

impl<F> EstablishDirectConnection<F>
    where F: FnOnce(&mut Core,
                    &mut EventLoop<Core>,
                    io::Result<(Token, Context, Socket)>,
                    PeerId) + Any
{
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 addr: SocketAddr,
                 peer_id: PeerId,
                 our_public_key: PublicKey,
                 name_hash: u64,
                 finish: F) {
        let token = core.get_new_token();
        let context = core.get_new_context();

        let socket = match Socket::connect(&addr) {
            Ok(socket) => socket,
            Err(SocketError::Io(error)) => {
                error!("Failed to connect socket: {:?}", error);
                finish(core, event_loop, Err(error), peer_id);
                return;
            }
            Err(_) => unreachable!(), // the other variant of SocketError is
                                      // serialisation error, which definitelly
                                      // won't happen on connect.
        };

        let event_set = EventSet::error() |
                        EventSet::hup() |
                        EventSet::readable() |
                        EventSet::writable();

        if let Err(error) = event_loop.register(&socket, token, event_set, PollOpt::edge()) {
            error!("Failed to register socket: {:?}", error);
            let _ = socket.shutdown();
            finish(core, event_loop, Err(error), peer_id);
            return;
        }

        let state = EstablishDirectConnection {
            socket: Some(socket),
            finish: Some(finish),
            token: token,
            context: context,
            peer_id: peer_id,
            handshake_send: HandshakeState::Ready,
            handshake_receive: HandshakeState::Ready,
        };

        let _ = core.insert_context(token, context);
        let _ = core.insert_state(context, Rc::new(RefCell::new(state)));
    }

    fn send_handshake(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let result = match self.handshake_send {
            HandshakeState::Ready => {
                self.socket.as_mut().unwrap().write(Message::Connect(self.public_key,
                                                                     self.name_hash))
            }
            HandshakeState::Started => {
                self.socket.as_mut().unwrap().flush();
            }
            HandshakeState::Finished => Ok(true)
        };

        match result {
            Ok(true) => self.handshake_send = HandshakeState::Finished,
            Ok(false) => self.handshake_send = HandshakeState::Started,
            Err(error) => {
                error!("Failed to write to socket: {:?}", error);
                // TODO: notify about the error
                // self.stop(core, event_loop, Err())
            }
        }
    }

    fn stop(&mut self,
            core: &mut Core,
            event_loop: &mut EventLoop<Core>,
            result: io::Result<(Token, Context, Socket)>)
    {
        let _ = core.remove_state(self.context);
        let _ = core.remove_context(self.token);

        if let Some(socket) = self.socket.take() {
            match event_loop.deregister(&socket) {
                Ok(()) => (),
                Err(e) => debug!("Error deregistering stream: {}", e),
            };
        }

        let finish = self.finish.take().unwrap();
        finish(core, event_loop, result, self.peer_id);
    }
}

impl<F> State for EstablishDirectConnection<F>
    where F: FnOnce(&mut Core,
                    &mut EventLoop<Core>,
                    io::Result<(Token, Context, Socket)>,
                    PeerId) + Any
{
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             _token: Token,
             event_set: EventSet) {
        if event_set.is_error() {
            let error = match self.socket.as_ref()
                                         .unwrap()
                                         .take_socket_error() {
                Ok(()) => io::Error::new(io::ErrorKind::Other, "Unknown error"),
                Err(e) => e,
            };

            self.stop(core, event_loop, Err(error));
        } else {
            if event_set.is_writable() {
                self.send_handshake(core, event_loop);
            }

            if event_set.is_readable() {
                self.receive_handshake(core, event_loop);
            }

            if self.handshake_send == HandshakeState::Finished &&
               self.handshake_receive == HandshakeState::Finished
            {
                let socket = self.socket.take().unwrap();
                let result = Ok((self.token, self.context, socket));
                self.stop(core, event_loop, result);
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let result = Err(io::Error::new(io::ErrorKind::Other, "Connect cancelled"));
        self.stop(core, event_loop, result);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

enum HandshakeState {
    Ready,
    Started,
    Finished,
}
