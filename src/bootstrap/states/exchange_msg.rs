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

pub struct ExchangeMsg {
    token: Token,
    context: Context,
    our_pk: Rc<PublicKey>,
    read_buf: Vec<u8>,
    read_len: usize,
    reader: BufReader<TcpStream>,
    socket: Socket,
    peer_addr: SocketAddr,
    cb: Callback,
    write_buf: Vec<u8>,
}

impl ExchangeMsg {
    fn new(core: &mut Core,
           event_loop: &mut EventLoop<Core>,
           token: Token,
           context: Context,
           our_pk: Rc<PublicKey>,
           version_hash: u64,
           socket: TcpStream,
           peer_addr: SocketAddr,
           cb: Callback) {
        let mut req = serialise(&CrustMsg::BootstrapReq((*our_pk).clone(), version_hash)).unwrap();
        let mut payload = Vec::with_capacity(mem::size_of::<u32>() + req.len());
        let _ = payload.write_u32::<LittleEndian>(payload.len() as u32);
        payload.append(&mut req);

        let exchange_msg = ExchangeMsg {
            token: token,
            context: context,
            our_pk: our_pk,
            read_buf: Vec::new(),
            read_len: 0,
            reader: BufReader::new(socket.try_clone().expect("Could not clone TcpStream")),
            socket: socket,
            peer_addr: peer_addr,
            cb: cb,
            write_buf: payload,
        };

        let exchange_msg = Rc::new(RefCell::new(exchange_msg));
        let _ = core.insert_state(context, exchange_msg.clone());
        exchange_msg.borrow_mut().write(core, event_loop);
    }

    fn read(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        let mut buf = vec![0; 1024];

        match self.socket.read(&mut buf) {
            Ok(bytes_rxd) => {
                if bytes_rxd == 0 {
                    println!("Mio rxd 0 byte read - terminating...");
                    return self.terminate_and_inform(core, event_loop);
                }

                buf.resize(bytes_rxd, 0);
                self.read_buf.append(&mut buf);
                if !self.read_impl() {
                    self.terminate_and_inform(core, event_loop);
                }
            }
            Err(e) => {
                if e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::Interrupted {
                    println!("Terminating due to error in reading mio_socket: {:?}", e);
                    self.terminate_and_inform(core, event_loop);
                }
            }
        }
    }

    fn read_impl(&mut self) -> bool {
        if self.read_len == 0 && self.read_buf.len() >= mem::size_of::<u32>() {
            self.read_len =
                Cursor::new(&self.read_buf[..mem::size_of::<u32>()])
                    .read_u32::<LittleEndian>()
                    .expect("Failed in parsing data_len.") as usize;
            if self.read_len > MAX_ALLOWED_PAYLOAD_SIZE {
                return false;
            }
            self.read_buf = self.read_buf.split_off(mem::size_of::<u32>());
        }

        if self.read_len > 0 && self.read_buf.len() >= self.read_len {
            let tail = self.read_buf.split_off(self.read_len);

            let msg: CrustMsg = match deserialise(&self.read_buf) {
                Ok(msg) => msg,
                Err(_) => return false,
            };

            match msg {
                CrustMsg::BootstrapResp(pk) => {
                    // Job done
                    let context = self.context;
                    self.cb(context, PeerId(pk));
                    let _ = core.remove_state(&self.context);
                    return true;
                }
                _ => return false,
            }

            // TODO(Spandan) make use of these to transition to next state once the major coding is
            //                done
            // self.read_buf = tail;
            // self.read_len = 0;
            // return Some(true);
        }

        true
    }

    fn write(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if !self.write_buf.is_empty() {
            match self.socket.write(&self.write_buf) {
                Ok(bytes_txd) => {
                    if bytes_txd < self.write_buf.len() {
                        self.write_buf = self.write_buf[bytes_txd..].to_owned();
                    } else {
                        self.write_buf.clear();
                    }
                }
                Err(e) => {
                    if e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::Interrupted {
                        self.terminate_and_inform(core, event_loop);
                    }
                }
            }
        }

        let event_set = if self.write_buf.is_empty() {
            EventSet::readable() | EventSet::error() | EventSet::hup()
        } else {
            EventSet::readable() | EventSet::writable() | EventSet::error() | EventSet::hup()
        };

        event_loop.reregister(&self.socket, self.token, event_set, PollOpt::edge())
                  .expect("Failed to reregister.");
    }

    fn terminate_and_inform(&mut self, core: &mut Core, event_loop: &mut EventLoop) {
        self.terminate(core, event_loop);
        let context = self.context;
        let peer_addr = self.peer_addr.clone();
        self.cb(context, Err(peer_addr));
    }
}

impl State for ExchangeMsg {
    fn execute(&mut self,
               core: &mut Core,
               event_loop: &mut EventLoop<Core>,
               token: Token,
               event_set: EventSet) {
        if event_set.is_error() || event_set.is_hup() {
            self.terminate_and_inform(core, event_loop);
        } else {
            if event_set.is_readable() {
                self.read(core, event_loop);
            }
            if event_set.is_writable() {
                self.write(core, event_loop);
            }
        }
    }

    fn terminate(&mut self, core: &mut Core, event_loop: &mut EventLoop<Core>) {
        if let Some(context) = core.remove_context(&self.token) {
            let _ = core.remove_state(&context);
        }
        let _ = event_loop.deregister(&self.socket);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
