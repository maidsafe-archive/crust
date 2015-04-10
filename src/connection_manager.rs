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
use std::collections::{HashMap};
use std::hash::{Hash};
use std::thread::spawn;
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use tcp_connections::{listen, connect_tcp, TcpReader, TcpWriter, upgrade_tcp};
use std::sync::{Arc, Mutex, Weak};
use std::sync::mpsc;
use cbor::{Encoder, Decoder};
use rustc_serialize::{Decodable, Encodable};
use std::fmt::Debug;

pub type Bytes   = Vec<u8>;

pub type IoResult<T> = Result<T, IoError>;

pub type IoReceiver<T> = Receiver<T>;
pub type IoSender<T>   = Sender<T>;

pub type SocketReader = TcpReader<Bytes>;
pub type SocketWriter = TcpWriter<Bytes>;

type WeakState<Id> = Weak<Mutex<State<Id>>>;

pub struct ConnectionManager<Id: Hash + Eq> {
    state: Arc<Mutex<State<Id>>>,
}

#[derive(Debug)]
pub enum Event<Id> {
    NewMessage(Id, Bytes),
    Connect(Id),
    Accept(Id, Bytes),
    LostConnection(Id),
}

struct Connection {
    writer_channel: mpsc::Sender<Bytes>,
    //socket_reader: 
}

struct State<Id: Hash + Eq> {
    our_id: Id,
    event_pipe: IoSender<Event<Id>>,
    connections: HashMap<Id, Connection>,
}

impl<Id> ConnectionManager<Id>
where Id : Hash + Eq + Send + 'static + Clone + Encodable + Decodable + Debug {

    pub fn new(our_id: Id, event_pipe: IoSender<Event<Id>>) -> ConnectionManager<Id> {
        let connections: HashMap<Id, Connection> = HashMap::new();
        let state = Arc::new(Mutex::new(State{ our_id: our_id,
                                               event_pipe: event_pipe,
                                               connections : connections }));
        ConnectionManager { state: state }
    }

    pub fn start_accepting(&self) -> IoResult<u16> {
        let weak_state = self.state.downgrade();
        let (event_receiver, listener) = try!(listen());
        let local_port = try!(listener.local_addr()).port();  // Consider backlog

        spawn(move || {
            for x in event_receiver.iter() {
                let (connection, _) = x;
                let s = weak_state.clone();
                spawn(move || {
                    let _ =
                        upgrade_tcp(connection)
                        .and_then(|(i, o)| { handle_accept(s, i, o) });
                });
            }
        });

        Ok(local_port)
    }

    pub fn connect(&self, endpoint: SocketAddr, msg: Bytes) -> IoResult<()> {
        let ws = self.state.downgrade();

        spawn(move || {
            let _ = connect_tcp(endpoint)
                    .and_then(|(i, o)| { handle_connect(ws, i, o, msg) });
        });

        Ok(())
    }

    /// Sends a message to address. Returns Ok(()) if the sending might succeed, and returns an
    /// Err if the address is not connected. Return value of Ok does not mean that the data will be
    /// received. It is possible for the corresponding connection to hang up immediately after this
    /// function returns Ok.
    pub fn send(&self, message: Bytes, id : Id)-> IoResult<()> {
        let ws = self.state.downgrade();

        let writer_channel = try!(lock_state(&ws, |s| {
                match s.connections.get(&id) {
                    Some(c) =>  Ok(c.writer_channel.clone()),
                    None => Err(io::Error::new(io::ErrorKind::NotConnected, "?"))
                }
        }));

        let send_result = writer_channel.send(message);
        let cant_send = io::Error::new(io::ErrorKind::BrokenPipe, "?");
        send_result.map_err(|_|cant_send)
    }

    pub fn drop_node(&self, id: Id) -> IoResult<()>{  // FIXME
        let mut ws = self.state.downgrade();
        lock_mut_state(&mut ws, |s: &mut State<Id>| {
            s.connections.remove(&id);
            Ok(())
        })
    }

    pub fn id(&self) -> Id {
        lock_state(&self.state.downgrade(), |s| Ok(s.our_id.clone())).unwrap()
    }

    pub fn stop(&self) {
        lock_mut_state(&self.state.downgrade(), |s| {
            s.connections.clear();
            Ok(())
        });
    }
}

fn lock_state<T, Id, F: Fn(&State<Id>) -> IoResult<T>>(state: &WeakState<Id>, f: F) -> IoResult<T>
where Id: Hash + Eq {
    state.upgrade().ok_or(io::Error::new(io::ErrorKind::Interrupted,
                                         "Can't dereference weak"))
    .and_then(|arc_state| {
        let opt_state = arc_state.lock();
        match opt_state {
            Ok(s)  => f(&s),
            Err(e) => Err(io::Error::new(io::ErrorKind::Interrupted, "?"))
        }
    })
}

fn lock_mut_state<T, Id, F: FnOnce(&mut State<Id>) -> IoResult<T>>(state: &WeakState<Id>, f: F) -> IoResult<T>
where Id: Hash + Eq {
    state.upgrade().ok_or(io::Error::new(io::ErrorKind::Interrupted,
                                         "Can't dereference weak"))
    .and_then(move |arc_state| {
        let opt_state = arc_state.lock();
        match opt_state {
            Ok(mut s)  => f(&mut s),
            Err(e) => Err(io::Error::new(io::ErrorKind::Interrupted, "?"))
        }
    })
}

fn handle_accept<Id>(mut state: WeakState<Id>,
                     i: SocketReader,
                     o: SocketWriter) -> IoResult<()>
where Id: Hash + Eq + Clone + Encodable + Decodable + Send + 'static + Debug {
    let our_id = try!(lock_state(&state, |s| Ok(s.our_id.clone())));
    let (i, o, his_data) = try!(exchange(i, o, encode(&(our_id, Bytes::new()))));
    let (his_id, his_msg): (Id, Bytes) = decode(his_data);
    register_connection(&mut state, his_id.clone(), i, o, Event::Accept(his_id, his_msg))
}

fn handle_connect<Id>(mut state: WeakState<Id>,
                      i: SocketReader,
                      o: SocketWriter,
                      msg: Bytes) -> IoResult<()>
where Id: Hash + Eq + Clone + Encodable + Decodable + Send + 'static + Debug {
    let our_id = try!(lock_state(&state, |s| Ok(s.our_id.clone())));
    let (i, o, his_data) = try!(exchange(i, o, encode(&(our_id, msg))));
    let (his_id, _): (Id, Bytes) = decode(his_data);
    register_connection(&mut state, his_id.clone(), i, o, Event::Connect(his_id))
}

fn register_connection<Id>( state: &mut WeakState<Id>
                          , his_id: Id
                          , i: SocketReader
                          , o: SocketWriter
                          , event_to_user: Event<Id>
                          ) -> IoResult<()>
where Id: Hash + Eq + Clone + Send + 'static + Debug {

    let state2 = state.clone();

    lock_mut_state(state, move |s: &mut State<Id>| {
        let (tx, rx) = mpsc::channel();
        start_writing_thread(state2.clone(), o, his_id.clone(), rx);
        start_reading_thread(state2, i, his_id.clone(), s.event_pipe.clone());
        s.connections.insert(his_id, Connection{writer_channel: tx});
        let _ = s.event_pipe.send(event_to_user);
        Ok(())
    })
}

fn unregister_connection<Id>(state: WeakState<Id>, his_id: Id)
where Id: Hash + Eq {
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
fn start_reading_thread<Id>(state: WeakState<Id>, i: SocketReader, his_id: Id, sink: IoSender<Event<Id>>)
where Id: Hash + Eq + Clone + Send + 'static + Debug {
    spawn(move || {
        for msg in i.iter() {
            if sink.send(Event::NewMessage(his_id.clone(), msg)).is_err() {
                break;
            }
        }
        //println!(">>>>>>>> end reading his_id {:?}", his_id.clone());
        unregister_connection(state, his_id);
    });
}

// pushing messges out to socket
fn start_writing_thread<Id>(state: WeakState<Id>, mut o: SocketWriter, his_id: Id, writer_channel: mpsc::Receiver<Bytes>)
where Id: Hash + Eq + Send + 'static + Debug + Clone {
    spawn(move || {
        for msg in writer_channel.iter() {
            if o.send(&msg).is_err() {
                break;
            }
        }
        //println!(">>>>>>>> end writing his_id {:?}", his_id.clone());
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
                                   "Can't exchage (send error)");
    let cant_recv = io::Error::new(io::ErrorKind::Other,
                                   "Can't exchage (send error)");

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
    use std::sync::mpsc::{Receiver, channel};
    use std::net::{SocketAddr};
    use std::str::FromStr;

#[test]
    fn connection_manager() {
        type Id = Vec<u8>;
        let run_cm = |cm: ConnectionManager<Id>, o: Receiver<Event<Id>>, my_port, his_port| {
            spawn(move ||{
                if my_port < his_port {
                    let addr = SocketAddr::from_str(&format!("127.0.0.1:{}", his_port)).unwrap();
                    assert!(cm.connect(addr).is_ok());
                }

                for i in o.iter() {
                    println!("Received event {:?}", i);
                    match i {
                        Event::NewConnection(_) => {
                            println!("Connected");
                            if cm.id() == vec![1] {
                                assert!(cm.send(vec![2], vec![2]).is_ok());
                            } else {
                                assert!(cm.send(vec![1], vec![1]).is_ok());
                            }
                        },
                        Event::NewMessage(x, y) => {
                            println!("new message !");
                            cm.stop();
                            //break;
                        }
                        _ => println!("unhandled"),
                    }
                }
            })
        };

        let (cm1_i, cm1_o) = channel();
        let cm1 = ConnectionManager::new(vec![1], cm1_i);
        let cm1_port = cm1.start_accepting().unwrap();

        let (cm2_i, cm2_o) = channel();
        let cm2 = ConnectionManager::new(vec![2], cm2_i);
        let cm2_port = cm2.start_accepting().unwrap();

        let runner1 = run_cm(cm1, cm1_o, cm1_port, cm2_port);
        let runner2 = run_cm(cm2, cm2_o, cm2_port, cm1_port);

        assert!(runner1.join().is_ok());
        assert!(runner2.join().is_ok());
    }
}
