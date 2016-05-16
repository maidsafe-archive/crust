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

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use mio::{Token, EventLoop, EventSet, PollOpt};
use mio::tcp::{Shutdown, TcpStream};
use std::collections::VecDeque;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::mem;

use core::{Core, State, StateHandle};
use event::Event;
use peer_id::PeerId;

pub struct ActiveConnection {
    _handle: StateHandle,
    peer_id: PeerId,
    token: Token,
    read_buf: Vec<u8>,
    read_len: u32,
    socket: TcpStream,
    write_queue: VecDeque<Vec<u8>>,
    event_tx: ::CrustEventSender,
}

impl ActiveConnection {
    pub fn new(core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               handle: StateHandle,
               socket: TcpStream,
               token: Token,
               event_tx: ::CrustEventSender) {
        println!("Entered state ActiveConnection");

        let peer_id = ::rand::random();

        let connection = ActiveConnection {
            _handle: handle,
            peer_id: peer_id,
            token: token,
            read_buf: Vec::new(),
            read_len: 0,
            socket: socket,
            write_queue: VecDeque::new(),
            event_tx: event_tx,
        };

        event_loop.reregister(&connection.socket,
                              token,
                              EventSet::readable() | EventSet::error() | EventSet::hup(),
                              PollOpt::edge())
                  .expect("Could not re-register socket with EventLoop<Core>");

        let _ = connection.event_tx.send(Event::NewConnection(peer_id));
        let _ = core.insert_state_handle(token, handle);
        let _ = core.insert_state(handle, connection);
    }

    fn read(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, token: Token) {
        // the mio reading window is max at 64k (64 * 1024)
        let mut buf = vec![0; 65536];
        match self.socket.read(&mut buf) {
            Ok(bytes_rxd) => {
                buf.resize(bytes_rxd, 0);
                self.read_buf.append(&mut buf);
                while self.read_data() {}
                if self.read_len <= ::MAX_DATA_LEN {
                    return;
                }
            }
            Err(e) => {
                if !(e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted) {
                    // remove self from core etc
                    // let _ = self.routing_tx.send(CrustMsg::LostPeer);
                }
            }
        }
        self.close(core, event_loop, token);
    }

    fn read_data(&mut self) -> bool {
        if self.read_len == 0 && self.read_buf.len() >= mem::size_of::<u32>() {
            self.read_len = Cursor::new(&self.read_buf[..mem::size_of::<u32>()])
                    .read_u32::<LittleEndian>().expect("Failed in parsing data_len.");
            if self.read_len > ::MAX_DATA_LEN {
                return false;
            }
            self.read_buf = self.read_buf.split_off(mem::size_of::<u32>());
        }
        // TODO: if data_len has been incorrectly parsed, the execution hangs.
        //       A time_out may need to be introduced to prevent it.
        if self.read_len > 0 && self.read_buf.len() as u32 >= self.read_len {
            let tail = self.read_buf.split_off(self.read_len as usize);
            let _ = self.event_tx.send(Event::NewMessage(self.peer_id, self.read_buf.clone()));
            self.read_buf = tail;
            self.read_len = 0;
            return true;
        }
        false
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, token: Token) {
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
                        self.close(core, event_loop, token);
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

    fn close(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, token: Token) {
        println!("Graceful Exit");
        event_loop.deregister(&self.socket).expect("Could not dereregister socket");
        let _ = self.socket.shutdown(Shutdown::Both);
        let _ = core.remove_state_by_token(&token);
        let _ = self.event_tx.send(Event::LostPeer(self.peer_id));
    }

}

impl State for ActiveConnection {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet) {
        assert_eq!(token, self.token);

        if event_set.is_error() {
            panic!("connection error");
            // let _ = routing_tx.send(Error - Could not connect);
        } else if event_set.is_hup() {
            self.close(core, event_loop, token);
        } else if event_set.is_readable() {
            self.read(core, event_loop, token);
        } else if event_set.is_writable() {
            self.write(core, event_loop, token);
        }
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>, data: Vec<u8>) {
        let mut vec_len = Vec::with_capacity(mem::size_of::<u32>());
        let _ = vec_len.write_u32::<LittleEndian>(data.len() as u32);
        self.write_queue.push_back(vec_len);
        self.write_queue.push_back(data);
        let token = self.token;
        self.write(core, event_loop, token);
    }
}
