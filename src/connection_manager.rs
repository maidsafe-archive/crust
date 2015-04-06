// Copyright 2015 MaidSafe.net limited
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, versicant_sendon 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

use std::net::{SocketAddr};
use std::io::Error as IoError;
use std::io;
use std::collections::HashMap;
use std::thread::spawn;
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use tcp_connections::{listen, connect_tcp, TcpReader, TcpWriter, upgrade_tcp};
use std::sync::{Arc, Mutex, Weak};
use std::sync::mpsc;
use cbor::{Encoder, Decoder};
use rustc_serialize::{Decodable, Encodable};

pub type Address = Vec<u8>;
pub type Bytes   = Vec<u8>;

pub type IoResult<T> = Result<T, IoError>;

pub type IoReceiver<T> = Receiver<T>;
pub type IoSender<T>   = Sender<T>;

pub type SocketReader = TcpReader<Bytes>;
pub type SocketWriter = TcpWriter<Bytes>;

type WeakState = Weak<Mutex<State>>;

pub struct ConnectionManager {
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
pub enum Event {
    NewMessage(Address, Bytes),
    NewConnection(Address),
    LostConnection(Address),
    AcceptingOn(u16)
}

struct Connection {
    writer_channel: mpsc::Sender<Bytes>
}

struct State {
    our_id: Address,
    event_pipe: IoSender<Event>,
    connections: HashMap<Address, Connection>,
}

impl ConnectionManager {

    pub fn new(our_id: Address, event_pipe: IoSender<Event>) -> ConnectionManager {
        let connections: HashMap<Address, Connection> = HashMap::new();
        let state = Arc::new(Mutex::new(State{ our_id: our_id,
                                               event_pipe: event_pipe,
                                               connections : connections }));
        let weak_state = state.downgrade();
        spawn(move || {
            let _ = start_accepting_connections(weak_state);
        });

        ConnectionManager { state: state }
    }

    pub fn connect(&self, endpoint: SocketAddr) -> IoResult<()> {
        let ws = self.state.downgrade();

        spawn(move || {
            let _ = connect_tcp(endpoint)
                    .and_then(|(i, o)| { handle_new_connection(ws, i, o) });
        });

        Ok(())
    }

    /// Sends a message to address. Returns Ok(()) if the sending might succeed, and returns an
    /// Err if the address is not connected. Return value of Ok does not mean that the data will be
    /// received. It is possible for the corresponding connection to hang up immediately after this
    /// function returns Ok.
    pub fn send(&self, message: Bytes, address : Address)-> IoResult<()> {
        let ws = self.state.downgrade();

        let writer_channel = try!(lock_state(&ws, |s| {
                match s.connections.get(&address) {
                    Some(c) =>  Ok(c.writer_channel.clone()),
                    None => Err(io::Error::new(io::ErrorKind::NotConnected, "?", None))
                }
        }));

        let send_result = writer_channel.send(message);
        let cant_send = io::Error::new(io::ErrorKind::BrokenPipe, "?", None);
        send_result.map_err(|_|cant_send)
    }

    pub fn drop_node(&self, address: Address) -> IoResult<()>{  // FIXME
        let mut ws = self.state.downgrade();
        lock_mut_state(&mut ws, |s: &mut State| {
            s.connections.remove(&address);
            Ok(())
        })
    }
}

fn lock_state<T, F: Fn(&State) -> IoResult<T>>(state: &WeakState, f: F) -> IoResult<T> {
    state.upgrade().ok_or(io::Error::new(io::ErrorKind::Interrupted,
                                         "Can't dereference weak",
                                         None))
    .and_then(|arc_state| {
        let opt_state = arc_state.lock();
        match opt_state {
            Ok(s)  => f(&s),
            Err(e) => Err(io::Error::new(io::ErrorKind::Interrupted, "?", None))
        }
    })
}

fn lock_mut_state<T, F: FnOnce(&mut State) -> IoResult<T>>(state: &WeakState, f: F) -> IoResult<T> {
    state.upgrade().ok_or(io::Error::new(io::ErrorKind::Interrupted,
                                         "Can't dereference weak",
                                         None))
    .and_then(move |arc_state| {
        let opt_state = arc_state.lock();
        match opt_state {
            Ok(mut s)  => f(&mut s),
            Err(e) => Err(io::Error::new(io::ErrorKind::Interrupted, "?", None))
        }
    })
}

fn start_accepting_connections(state: WeakState) -> IoResult<()> {
    println!("start_accepting_connections");
    let (event_receiver, listener) = try!(listen());

    let local_port = try!(listener.local_addr()).port();  // Consider backlog

    try!(lock_state(&state, |s| {
        s.event_pipe.send(Event::AcceptingOn(local_port)).or(Ok(()))
    }));
    loop {
        match event_receiver.iter().next() {
            Some(x) => {
                let (connection, _) = x;
                let s = state.clone();
                spawn(move|| {
                    let _ =
                        upgrade_tcp(connection)
                        .and_then(|(i, o)| { handle_new_connection(s, i, o) });
                });
            },
            None => {break;}
        }
    }
    Ok(())
}

fn handle_new_connection(mut state: WeakState, i: SocketReader, o: SocketWriter) -> IoResult<()> {
    let our_id = try!(lock_state(&state, |s| Ok(s.our_id.clone())));
    let (i, o, his_data) = try!(exchange(i, o, encode(&our_id)));
    let his_id: Address = decode(his_data);
    println!("handle_new_connection our_id:{:?} his_id:{:?}", our_id, his_id);
    register_connection(&mut state, his_id, i, o)
}

fn register_connection( state: &mut WeakState
                      , his_id: Address
                      , i: SocketReader
                      , o: SocketWriter
                      ) -> IoResult<()> {

    let state2 = state.clone();

    lock_mut_state(state, move |s: &mut State| {
        let (tx, rx) = mpsc::channel();
        start_writing_thread(state2.clone(), o, his_id.clone(), rx);
        start_reading_thread(state2, i, his_id.clone(), s.event_pipe.clone());
        s.connections.insert(his_id.clone(), Connection{writer_channel: tx});
        let _ = s.event_pipe.send(Event::NewConnection(his_id));
        Ok(())
    })
}

fn unregister_connection(state: WeakState, his_id: Address) {
    let _ = lock_mut_state(&state, |s| {
        if s.connections.remove(&his_id).is_some() {
            // Only send the event if the connection was there
            // to avoid duplicate events.
            let _ = s.event_pipe.send(Event::LostConnection(his_id));
        }
        Ok(())
    });
}

// pushing events out to event_pipe
fn start_reading_thread(state: WeakState, i: SocketReader, his_id: Address, sink: IoSender<Event>) {
    spawn(move || {
        loop {
            match i.iter().next() {
                Some(msg) => {
                    if sink.send(Event::NewMessage(his_id.clone(), msg)).is_err() {
                        break;
                    }
                },
                None => { break; }
            }
        }
        unregister_connection(state, his_id);
    });
}

// pushing messges out to socket
fn start_writing_thread(state: WeakState, mut o: SocketWriter, his_id: Address, writer_channel: mpsc::Receiver<Bytes>) {
    spawn(move || {
         loop {
            let mut writer_iter = writer_channel.iter();
            let msg = match writer_iter.next() {
                None => { break; }
                Some(msg) => {
                    if o.send(&msg).is_err() {
                        break;
                    }
                }
            };
        }
        unregister_connection(state, his_id);
        });
}

// FIXME need timer
fn exchange(socket_input:  SocketReader, socket_output: SocketWriter, data: Bytes)
            -> IoResult<(SocketReader, SocketWriter, Bytes)>
{
    let (output, input) = mpsc::channel();

    spawn(move || {
        let mut s = socket_output;
        if s.send(&data).is_err() {
            return;
        }
        let _ = output.send(s);
    });

    let opt_result = socket_input.recv();
    let opt_send_result = input.recv();

    let cant_send = io::Error::new(io::ErrorKind::Other,
                                   "Can't exchage (send error)", None);
    let cant_recv = io::Error::new(io::ErrorKind::Other,
                                   "Can't exchage (send error)", None);

    let socket_output = try!(opt_send_result.map_err(|_|cant_send));
    let result = try!(opt_result.map_err(|_|cant_recv));

    Ok((socket_input, socket_output, result))
}

fn encode<T>(value: &T) -> Bytes where T: Encodable
{
    let mut enc = Encoder::from_memory();
    let _ = enc.encode(&[value]);
    enc.into_bytes()
}

// TODO(Peter): This should return Option<T>
fn decode<T>(bytes: Bytes) -> T where T: Decodable {
    let mut dec = Decoder::from_bytes(&bytes[..]);
    dec.decode().next().unwrap().unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use std::thread::spawn;
    use std::sync::mpsc::channel;
    use std::net::{SocketAddr};
    use std::str::FromStr;

#[test]
    fn connection_manager() {
        let spawn_node = |id: Vec<u8>| {
            spawn(||{
                let id_copy = id.clone();
                let (i, o) = channel();
                let cm = ConnectionManager::new(id, i);
                loop {
                //for i in o.into_blocking_iter() {
                    match o.iter().next() {
                        Some(i) => {
                            println!("Received event {:?}", i);
                            match i {
                                Event::AcceptingOn(port) => {
                                    if port != 5483 {
                                        let addr = SocketAddr::from_str("127.0.0.1:5483").unwrap();
                                        assert!(cm.connect(addr).is_ok());
                                    }
                                },
                                Event::NewConnection(_) => {
                                    println!("Connected");
                                    if id_copy == vec![1] {
                                        assert!(cm.send(vec![2], vec![2]).is_ok());
                                    } else {
                                        assert!(cm.send(vec![1], vec![1]).is_ok());
                                    }
                                },
                                Event::NewMessage(x, y) => {
                                    println!("new message !");
                                    break;
                                }
                                _ => println!("unhandled"),
                            }
                        },
                        None => { break; }
                    }
                }
            })
        };

        let t1 = spawn_node(vec![1]);
        let t2 = spawn_node(vec![2]);

        assert!(t1.join().is_ok());
        assert!(t2.join().is_ok());
    }
}
