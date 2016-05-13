use std::io::{Read, Write, BufReader};
use std::collections::{HashMap, VecDeque};

use state::State;
use std::sync::{Arc, Mutex};
use std::rc::Rc;
use std::cell::RefCell;
use core::{Core, Context};
use mio::{Token, EventLoop, EventSet, PollOpt};
use mio::tcp::TcpStream;
use std::io::ErrorKind;
use event::Event;

pub struct ActiveConnection {
    peer_id: u64,
    cm: Arc<Mutex<HashMap<u64, Context>>>,
    token: Token,
    _context: Context,
    _read_buf: Vec<u8>,
    reader: BufReader<TcpStream>,
    socket: TcpStream,
    write_queue: VecDeque<Vec<u8>>,
    routing_tx: ::CrustEventSender,
}

impl ActiveConnection {
    pub fn new(core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               cm: Arc<Mutex<HashMap<u64, Context>>>,
               context: Context,
               socket: TcpStream,
               routing_tx: ::CrustEventSender) {
        println!("Entered state ActiveConnection");

        let token = core.get_new_token();
        let peer_id = ::rand::random();

        let connection = ActiveConnection {
            peer_id: peer_id,
            cm: cm,
            token: token,
            _context: context.clone(),
            _read_buf: Vec::new(),
            reader: BufReader::new(socket.try_clone().expect("Could not clone TcpStream")),
            socket: socket,
            write_queue: VecDeque::new(),
            routing_tx: routing_tx,
        };

        event_loop.reregister(&connection.socket,
                              token,
                              EventSet::readable() | EventSet::error() | EventSet::hup(),
                              PollOpt::edge())
                  .expect("Could not re-register socket with EventLoop<Core>");

        let _ = connection.cm.lock().unwrap().insert(peer_id, context.clone());
        let _ = connection.routing_tx.send(Event::NewConnection(peer_id));
        let _ = core.insert_context(token, context.clone());
        let _ = core.insert_state(context, Rc::new(RefCell::new(connection)));
    }

    fn read(&mut self, _core: &mut Core, _event_loop: &mut EventLoop<Core>, _token: Token) {
        let mut buf = vec![0; 10];
        match self.reader.read(&mut buf) {
            Ok(_bytes_rxd) => {
                let _ = self.routing_tx.send(Event::NewMessage(self.peer_id, buf));
            }
            Err(e) => {
                if !(e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted) {
                    // remove self from core etc
                    // let _ = self.routing_tx.send(CrustMsg::LostPeer);
                }
            }
        }
    }

    fn write(&mut self, _core: &mut Core, event_loop: &mut EventLoop<Core>, _token: Token) {
        if let Some(mut data) = self.write_queue.pop_front() {
            match self.socket.write(&data) {
                Ok(bytes_txd) => {
                    if bytes_txd < data.len() {
                        data = data[bytes_txd..].to_owned();
                        self.write_queue.push_front(data);
                    }
                }
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted {
                        self.write_queue.push_front(data);
                    } else {
                        // remove self from core etc
                        // let _ = self.routing_tx.send(CrustMsg::LostPeer);
                    }
                }
            }
        }

        let event_set = if self.write_queue.is_empty() {
            EventSet::readable() | EventSet::error() | EventSet::hup()
        } else {
            EventSet::readable() | EventSet::writable() | EventSet::error() | EventSet::hup()
        };

        event_loop.reregister(&self.socket, self.token, event_set, PollOpt::edge())
                  .expect("Could not reregister socket");
    }
}

impl State for ActiveConnection {
    fn execute(&mut self,
               core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               token: Token,
               event_set: EventSet) {
        assert_eq!(token, self.token);

        if event_set.is_error() {
            panic!("connection error");
            // let _ = routing_tx.send(Error - Could not connect);
        } else if event_set.is_hup() {
            let context = core.remove_context(&token).expect("Context not found");
            let _ = core.remove_state(&context).expect("State not found");

            println!("Graceful Exit");
        } else if event_set.is_readable() {
            self.read(core, event_loop, token);
        } else if event_set.is_writable() {
            self.write(core, event_loop, token);
        }
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, data: Vec<u8>) {
        self.write_queue.push_back(data);
        let token = self.token;
        self.write(core, event_loop, token);
    }
}
