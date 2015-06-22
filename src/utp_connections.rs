// Copyright 2015 MaidSafe.net limited.
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

use utp::UtpListener;
use utp::UtpCloneableSocket as UtpSocket;
use std::net::SocketAddr;
use std::io;
use std::io::{Read, Write, BufReader, BufWriter, ErrorKind, Result};
use std::io::Result as IoResult;
use std::ops::Deref;
use cbor::{Encoder, Decoder};
use std::thread;
use rustc_serialize::{Decodable, Encodable};
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};

pub type UtpReader<T> = Receiver<T>;
pub type UtpWriter<T> = OutUtpStream<T>;

pub type InUtpStream<T> = Receiver<T>;

pub struct UtpStream {
    socket: UtpSocket,
}

//impl UtpStream {
//
//    /// Returns the socket address of the local half of this uTP connection.
//    pub fn local_addr(&self) -> Result<SocketAddr> {
//        self.socket.local_addr()
//    }
//}

impl Read for UtpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.socket.recv_from(buf).map(|(read, _src)| read)
    }
}

impl Write for UtpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.socket.send_to(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.socket.flush()
    }
}

impl Into<UtpStream> for UtpSocket {
    fn into(self) -> UtpStream {
        UtpStream { socket: self }
    }
}

impl Deref for UtpStream {
    type Target = UtpSocket;

    fn deref(&self) -> &UtpSocket {
        &self.socket
    }
}


pub struct OutUtpStream<T> {
    stream: Option<Sender<T>>,
}

impl <T> OutUtpStream<T>
where T: Encodable {

    pub fn new(s: Sender<T>) -> OutUtpStream<T> {
        OutUtpStream { stream: Some(s) }
    }
    
    pub fn send(&self, m: T) -> Result<()> {
        if let Some(ref s) = self.stream {
            return s.send(m).map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "can't send"))
        }
        Err(io::Error::new(io::ErrorKind::NotConnected, "not connected"))
    }
    
    #[allow(dead_code)]  // This code isn't dead, but without this modifier it won't compile
    pub fn close(&mut self) -> Result<()> {
        self.stream = None;
        Ok(())
    }
}

impl <T> Drop for OutUtpStream<T> {
    fn drop(&mut self) {
        println!("OutUtpStream drops");
    }
}


/// Connect to a peer and open a send-receive pair.  See `upgrade` for more details.
pub fn connect_utp<'a, 'b, I, O>(addr: SocketAddr) -> IoResult<(InUtpStream<I>, OutUtpStream<O>)>
        where I: Send + Decodable + 'static, O: Send + Encodable + 'static {
    Ok(try!(upgrade_utp(try!(UtpSocket::connect(&addr)))))
}

/// Starts listening for connections on this ip and port.
/// Returns:
/// * A receiver of Utp socket objects.  It is recommended that you `upgrade` these.
#[allow(unused)]
pub fn listen(port: u16) -> IoResult<(Receiver<(UtpSocket, SocketAddr)>, u16)> {
    let utp_listener = {
        /*if let Ok(listener) = UtpSocket::bind(("::", port)) {
            listener
        } else if let Ok(listener) = UtpSocket::bind(("::", 0)) {
            listener
        } else*/ if let Ok(listener) = UtpListener::bind(("0.0.0.0", port)) {
            listener
        } else {
            try!(UtpListener::bind(("0.0.0.0", 0)))
        }
    };
    let port = utp_listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    let _ = thread::Builder::new().name("UTP listen".to_string()).spawn(move || {
        loop {
            // if tx.is_closed() {       // FIXME (Prakash)
            //     break;
            // }
            match utp_listener.accept() {  // Blocks until next incoming connection
                Ok((socket, addr)) => {
                    let cloned = socket.into();
                    if tx.send((cloned, addr)).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::TimedOut => {
                    continue;
                }
                Err(_) => {
                    //let _  = tx.error(e);
                    break;
                }
            }
        }
        println!("UTP listen exits");
    });
    Ok((rx, port))
}

/// Upgrades a newly connected UtpSocket to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.  If there is an error decoding or encoding
/// values, that respective part is shut down.
pub fn upgrade_utp<'a, 'b, I, O>(newconnection: UtpSocket) -> IoResult<(InUtpStream<I>, OutUtpStream<O>)>
where I: Send + Decodable + 'static, O: Send + Encodable + 'static {
    // Clone the new connection socket
    let newconnection2 = newconnection.try_clone();
    let mut newconnection_ = newconnection.try_clone();
    let mut newconnection2_ = newconnection.try_clone();
    // Convert the new connection sockets into streams
    let stream_read : UtpStream = newconnection.into();
    let stream_write : UtpStream = newconnection2.into();
    
    // Configure a reading thread
    let (in_snd, in_rec) = mpsc::channel();
    let _ = thread::Builder::new().name("UTP reader".to_string()).spawn(move || {
        let mut buffer = BufReader::new(stream_read);
        {
            let mut decoder = Decoder::from_reader(&mut buffer);
            loop {
                let data = match decoder.decode().next() {
                  Some(a) => a,
                  None => { break; }
                  };
                match data {
                    Ok(a) => {
                        // Try to send, and if we can't, then the channel is closed.
                        if in_snd.send(a).is_err() {
                            break;
                        }
                    },
                    // if we can't decode, close the stream with an error.
                    Err(_) => {
                        // let _ = in_snd.error(e);
                        break;
                    }
                }
            }
            println!("UTP reader exits");
        }
        let _ = newconnection_.close();
    });

    // Configure a sending thread    
    let (out_snd, out_rec) = mpsc::channel();
    let _ = thread::Builder::new().name("UTP writer".to_string()).spawn(move || {
        let mut buffer = BufWriter::new(stream_write);
        {
            let mut encoder = Encoder::from_writer(&mut buffer);
            loop {
                let data = out_rec.recv();
                if data.is_err() { break; }
                let data = data.unwrap();
                let _ = encoder.encode(&[&data]);
            }
            println!("UTP writer exits");
        }
        let _ = newconnection2_.close();
    });
    
    Ok((in_rec, OutUtpStream::new(out_snd)))
}


#[cfg(test)]
mod test {
    use super::*;
    use std::thread;
    use std::net::SocketAddr;
    use std::str::FromStr;

 #[test]
    fn test_small_stream() {
        let (event_receiver, port) = listen(5483).unwrap();
        let (i, mut o) = connect_utp(SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap()).unwrap();

        for x in 0u64 .. 10u64 {
            if o.send(x).is_err() { break; }
        }
        let _ = o.close();
        let _ = thread::spawn(move || {
            for x in event_receiver.iter() {
                let (connection, _) = x;
                // Spawn a new thread for each connection that we get.
                let _ = thread::spawn(move || {
                    let (i, o) = upgrade_utp(connection).unwrap();
                    for x in i.iter() {
                        let x:u32 = x;
                        if o.send((x, x + 1)).is_err() { break; }
                    }
                });
            }
        });
        // Collect everything that we get back.
        let mut responses: Vec<(u64, u64)> = Vec::new();
        for a in i.iter() {
            responses.push(a);
        }
        // println!("Responses: {:?}", responses);
        assert_eq!(10, responses.len());
    }

#[test]
    fn test_multiple_nodes_small_stream() {
        const MSG_COUNT: usize = 5;
        const NODE_COUNT: usize = 101;

        let (event_receiver, port) = listen(5483).unwrap();
        let mut vector_senders = Vec::new();
        let mut vector_receiver = Vec::new();
        for _ in 0..NODE_COUNT {
            let (i, o) = connect_utp(SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap()).unwrap();
            let boxed_output: Box<OutUtpStream<u64>> = Box::new(o);
            vector_senders.push(boxed_output);
            let boxed_input: Box<InUtpStream<(u64, u64)>> = Box::new(i);
            vector_receiver.push(boxed_input);
        }

        //  send
        for v in &mut vector_senders {
            for x in 0u64 .. MSG_COUNT as u64 {
                if v.send(x).is_err() { break; }
            }
        }

        //  close sender
        loop {
           let _ = match vector_senders.pop() {
                None => break, // empty
                Some(mut sender) => sender.close(),
            };
        }


        // event_receiver
        let _ = thread::spawn(move || {
            for x in event_receiver.iter() {
                let (connection, _) = x;
                // Spawn a new thread for each connection that we get.
                let _ = thread::spawn(move || {
                    let (i, o) = upgrade_utp(connection).unwrap();
                    for x in i.iter() {
                        let x:u32 = x;
                        if o.send((x, x + 1)).is_err() { break; }
                    }
                });
            }
        });

        // Collect everything that we get back.
        let mut responses: Vec<(u64, u64)> = Vec::new();

        loop {
           let _ = match vector_receiver.pop() {
                None => break, // empty
                Some(receiver) => {
                    for a in receiver.iter() {
                        responses.push(a);
                    }
                }
            };
        }

        // println!("Responses: {:?}", responses);
        assert_eq!((NODE_COUNT * MSG_COUNT), responses.len());
    }


 // #[test]
    // fn graceful_port_close() {
        //use std::net::{TcpListener};
        //use std::sync::mpsc;
        //use std::thread::spawn;

        //let tcp_listener = TcpListener::bind((("0.0.0.0"), 0)).unwrap();

        //let tcp_listener2 = tcp_listener.try_clone().unwrap();
        //let t = spawn(move || {
        //    loop {
        //        match tcp_listener2.accept() {
        //            Ok(_) => { }
        //            Err(e) => { break; }
        //        }
        //    }
        //});

        //drop(tcp_listener);
        //assert!(t.join().is_ok());
        ////let first_binding;

        ////{
        ////    let (event_receiver, listener) = listen().unwrap();
        ////    first_binding = listener.local_addr().unwrap();
        ////}
        ////{
        ////    let (event_receiver, listener) = listen().unwrap();
        ////    let second_binding = listener.local_addr().unwrap();
        ////    assert_eq!(first_binding.port(), second_binding.port());
        ////}
    // }

// #[test]
// fn test_stream_large_data() {
//     // Has to be sent over several packets
//     const LEN: usize = 1024 * 1024;
//     let data: Vec<u8> = (0..LEN).map(|idx| idx as u8).collect();
//     assert_eq!(LEN, data.len());
//
//     let d = data.clone(\;
//     let receiver_addr = next_test_ip4();
//     let mut receiver = UtpStream::bind(receiver_addr);
//
//     thread::spawn(move || {
//         let mut sender = iotry!(UtpStream::connect(receiver_addr));
//         iotry!(sender.write(&d[..]));
//         iotry!(sender.close());
//     });
//
//     let read = iotry!(receiver.read_to_end());
//     assert!(!read.is_empty());
//     assert_eq!(read.len(), data.len());
//     assert_eq!(read, data);
// }

}
