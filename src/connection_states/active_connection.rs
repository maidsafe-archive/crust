// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use core::{Core, Context};
use event::Event;
use mio::{Token, EventLoop, EventSet, PollOpt};
use mio::tcp::TcpStream;
use peer_id::PeerId;
use state::State;

pub struct ActiveConnection {
    peer_id: PeerId,
    cm: Arc<Mutex<HashMap<PeerId, Context>>>,
    token: Token,
    _context: Context,
    read_buf: Vec<u8>,
    read_len: u64,
    socket: TcpStream,
    write_queue: VecDeque<Vec<u8>>,
    routing_tx: ::CrustEventSender,
}

impl ActiveConnection {
    pub fn new(core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               cm: Arc<Mutex<HashMap<PeerId, Context>>>,
               context: Context,
               socket: TcpStream,
               routing_tx: ::CrustEventSender,
               token: Token) {
        println!("Entered state ActiveConnection");

        let peer_id = ::rand::random();

        let connection = ActiveConnection {
            peer_id: peer_id,
            cm: cm,
            token: token,
            _context: context.clone(),
            read_buf: Vec::new(),
            read_len: 0,
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
        // the mio reading window is max at 64k (64 * 1024)
        let mut buf = vec![0; 65536];
        match self.socket.read(&mut buf) {
            Ok(bytes_rxd) => {
                if bytes_rxd == 10 && buf[0] == 0xFF && buf[9] == 0xFF {
                    self.read_len = 0;
                    for i in 1..8 {
                        self.read_len += buf[i] as u64;
                        self.read_len = self.read_len << 8;
                    }
                    self.read_len += buf[8] as u64;
                    println!("expecting data len {}", self.read_len);
                } else {
                    buf.resize(bytes_rxd, 0);
                    self.read_buf.append(&mut buf);
                    if self.read_buf.len() as u64 >= self.read_len {
                        let _ = self.routing_tx.send(Event::NewMessage(self.peer_id, self.read_buf.clone()));
                        self.read_len = 0;
                        self.read_buf.clear();
                    }
                }
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
        let mut len = data.len() as u64;
        let mut vec_len : Vec<u8> = vec![0xFF, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0xFF];
        for i in 1..9 {
            if len <= 0xFF {
                vec_len[9 - i] = len as u8;
                break;
            }
            let mut remain = len >> 8;
            remain = remain << 8;
            let value : u64 = len - remain;
            vec_len[9 - i] = value as u8;
            len = len >> 8;
        }

        self.write_queue.push_back(vec_len);
        self.write_queue.push_back(data);
        let token = self.token;
        self.write(core, event_loop, token);
    }
}
