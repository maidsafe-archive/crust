use std::net::SocketAddr;
use std::sync::mpsc::Sender;

use state::State;
use std::collections::HashMap;
use connection_states::ActiveConnection;
use std::sync::{Arc, Mutex};
use std::rc::Rc;
use std::cell::RefCell;
use service::CrustMsg;
use core::{Core, Context};
use mio::{PollOpt, Token, EventLoop, EventSet};
use mio::tcp::TcpStream;


pub struct EstablishConnection {
    cm: Arc<Mutex<HashMap<u64, Context>>>,
    context: Context,
    routing_tx: Sender<CrustMsg>,
    socket: Option<TcpStream>, // Allows moving out without needing to clone the stream
}

impl EstablishConnection {
    pub fn new(core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               cm: Arc<Mutex<HashMap<u64, Context>>>,
               routing_tx: Sender<CrustMsg>,
               peer_contact_info: SocketAddr) {
        let context = core.get_new_context();
        let socket = TcpStream::connect(peer_contact_info).expect("Could not connect to peer");
        let connection = EstablishConnection {
            cm: cm,
            context: context.clone(),
            routing_tx: routing_tx,
            socket: Some(socket),
        };

        let token = core.get_new_token();
        event_loop.register(connection.socket.as_ref().expect("Logic Error"),
                            token,
                            EventSet::readable() | EventSet::error(),
                            PollOpt::edge())
                  .expect("Could not register socket with EventLoop<Core>");

        let _ = core.insert_context(token, context.clone());
        let _ = core.insert_state(context, Rc::new(RefCell::new(connection)));
    }
}

impl State for EstablishConnection {
    fn execute(&mut self,
               core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               token: Token,
               event_set: EventSet) {
        if event_set.is_readable() {
            let context = core.remove_context(token).expect("Context not found");
            let _ = core.remove_state(context).expect("State not found");

            ActiveConnection::new(core,
                                  event_loop,
                                  self.context.clone(),
                                  self.socket.take().expect("Logic Error"),
                                  self.routing_tx.clone());
        } else if event_set.is_error() {
            panic!("connection error");
            // let _ = routing_tx.send(Error - Could not connect);
        }
    }
}
