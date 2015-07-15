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

#![allow(unsafe_code)]
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};
use std::slice;
use std::io::{Read, BufReader, ErrorKind, Error, Result};
use std::io::Result as IoResult;
use cbor::{Encoder, Decoder};
use std::marker::PhantomData;
use rustc_serialize::{Decodable, Encodable};
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use libc;
use std::mem;
use std::ptr;
use utp_crust::*;

pub type UtpSocket = utp_crust_socket;
pub type UtpReader<T> = InUtpStream<T>;
pub type UtpWriter<T> = OutUtpStream<T>;


fn sockaddr_to_addr(_storage: *const ::libc::c_void,
                    len: usize) -> Result<SocketAddr> {
    let storage = _storage as *const ::libc::sockaddr_storage;
    unsafe {
        match (*storage).ss_family as libc::c_int {
            libc::AF_INET => {
                assert!(len >= mem::size_of::<libc::sockaddr_in>());
                let s=*(storage as *const libc::sockaddr_in);
                let o=u32::from_be(s.sin_addr.s_addr);
                Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new((o >> 24) as u8,
                                                                  (o >> 16) as u8,
                                                                  (o >> 8) as u8,
                                                                  (o) as u8), u16::from_be(s.sin_port))))
            }
            libc::AF_INET6 => {
                assert!(len >= mem::size_of::<libc::sockaddr_in6>());
                let s=*(storage as *const libc::sockaddr_in6);
                let o=[u16::from_be(s.sin6_addr.s6_addr[0]),
                      u16::from_be(s.sin6_addr.s6_addr[1]),
                      u16::from_be(s.sin6_addr.s6_addr[2]),
                      u16::from_be(s.sin6_addr.s6_addr[3]),
                      u16::from_be(s.sin6_addr.s6_addr[4]),
                      u16::from_be(s.sin6_addr.s6_addr[5]),
                      u16::from_be(s.sin6_addr.s6_addr[6]),
                      u16::from_be(s.sin6_addr.s6_addr[7])];
                Ok(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]),
                                                    u16::from_be(s.sin6_port),
                                                    u32::from_be(s.sin6_flowinfo),
                                                    u32::from_be(s.sin6_scope_id))))
            }
            _ => {
                Err(Error::new(ErrorKind::InvalidInput, "invalid argument"))
            }
        }
    }
}

#[repr(C)]
struct ListenerEventCallback {
    pub tx : Sender<(UtpSocket, SocketAddr)>,
}

extern "C" fn listener_event_callback(_: utp_crust_socket, ev: utp_crust_event_code, data: *const ::libc::c_void, bytes: ::libc::size_t, privdata: *mut ::libc::c_void) {
    let this = privdata as *mut ListenerEventCallback;
    match ev {
        UTP_CRUST_SOCKET_CLEANUP => {
            drop(unsafe { Box::from_raw(this) });
        },
        UTP_CRUST_NEW_CONNECTION => {
            let addr = sockaddr_to_addr(data, bytes as usize).unwrap();
            println!("utp_connections: new connection on listening socket from {}", addr);
            // Create a new socket and connect it to the remote
            let mut utp_socket : utp_crust_socket = 0;
            let mut port : u16 = 0;
            if -1 == unsafe { utp_crust_create_socket(&mut utp_socket, &mut port, 0, Some(event_callback), ptr::null_mut()) } {
                panic!("Failed to create new socket");
            }
            if -1 == unsafe { utp_crust_connect(utp_socket, data as *const ::libc::sockaddr, bytes as ::libc::socklen_t) } {
                panic!("Failed to connect newly created socket");
            }
            // Return the newly created socket
            let _ = unsafe {&(*this)}.tx.send((utp_socket, addr));
            println!("utp_connections: sent newly accepted connection {} to UTP listen thread", utp_socket);
        },
        _ => (),
    }
}

/// Connect to a peer and open a send-receive pair.  See `upgrade` for more details.
pub fn connect_utp<'a, 'b, I, O>(addr: SocketAddr) -> IoResult<(InUtpStream<I>, OutUtpStream<O>)>
        where I: Send + Decodable + 'static, O: Send + Encodable + 'static {
    let mut utp_socket : utp_crust_socket = 0;
    let mut port : u16 = 0;
    if -1 == unsafe { utp_crust_create_socket(&mut utp_socket, &mut port, 0, Some(event_callback), ptr::null_mut()) } {
        return Err(Error::last_os_error());
    }
    match addr {
        SocketAddr::V4(a) => {
            let length = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let o=a.ip().octets();
            let address = ::libc::sockaddr_in {
                sin_family : libc::AF_INET as u16,
                sin_port : u16::to_be(a.port()),
                sin_addr : libc::in_addr { s_addr : ((o[3] as u32)<<24)|((o[2] as u32)<<16)|((o[1] as u32)<<8)|(o[0] as u32) },
                sin_zero : [0; 8],
            };
            let _address : *const libc::sockaddr_in = &address;
            if -1 == unsafe { utp_crust_connect(utp_socket, _address as *const libc::sockaddr, length) } {
                return Err(Error::last_os_error());
            }
        },
        SocketAddr::V6(a) => {
            let length = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let o=a.ip().segments();
            let address = ::libc::sockaddr_in6 {
                sin6_family : libc::AF_INET6 as u16,
                sin6_port : u16::to_be(a.port()),
                sin6_flowinfo : 0,
                sin6_scope_id : 0,
                sin6_addr : libc::in6_addr { s6_addr : [
                    u16::to_be(o[0]),
                    u16::to_be(o[1]),
                    u16::to_be(o[2]),
                    u16::to_be(o[3]),
                    u16::to_be(o[4]),
                    u16::to_be(o[5]),
                    u16::to_be(o[6]),
                    u16::to_be(o[7]),
                ] },
            };
            let _address : *const libc::sockaddr_in6 = &address;
            if -1 == unsafe { utp_crust_connect(utp_socket, _address as *const libc::sockaddr, length) } {
                return Err(Error::last_os_error());
            }
        },
    };
    Ok(try!(upgrade_utp(utp_socket)))
}

/// Starts listening for connections on this ip and port.
/// Returns:
/// * A receiver of Utp socket objects.  It is recommended that you `upgrade` these.
pub fn listen(mut port: u16) -> IoResult<(Receiver<(UtpSocket, SocketAddr)>, u16)> {
    let (tx, rx) = mpsc::channel();
    let data = Box::new(ListenerEventCallback { tx : tx });
    let mut utp_listener : utp_crust_socket = 0;
    if -1 == unsafe { utp_crust_create_socket(&mut utp_listener, &mut port, UTP_CRUST_LISTEN, Some(listener_event_callback), Box::into_raw(data) as *mut ::libc::c_void) } {
        return Err(Error::last_os_error());
    }
    Ok((rx, port))
}


#[repr(C)]
struct EventCallback {
    pub in_snd : Sender<Vec<u8>>,
}

extern "C" fn event_callback(_: utp_crust_socket, ev: utp_crust_event_code, data: *const ::libc::c_void, bytes: ::libc::size_t, privdata: *mut ::libc::c_void) {
    let this = privdata as *mut EventCallback;
    if !this.is_null() {
        match ev {
            UTP_CRUST_SOCKET_CLEANUP => {
                println!("utp_connections socket cleanup");
                drop(unsafe { Box::from_raw(this) });
            },
            UTP_CRUST_LOST_CONNECTION => {
                println!("utp_connections lost connection");
                drop(unsafe {&(*this).in_snd});
            },
            UTP_CRUST_NEW_MESSAGE => {
                let e = unsafe {&(*this)}.in_snd.send(unsafe { slice::from_raw_parts(data as *const u8, bytes as usize).to_vec() });
                println!("utp_connections: new message mpsc send returns error={}", e.is_err());
            },
            _ => (),
        }
    }
}


/// Upgrades a newly connected UtpSocket to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.  If there is an error decoding or encoding
/// values, that respective part is shut down.
pub fn upgrade_utp<'a, 'b, I, O>(newconnection: UtpSocket) -> IoResult<(InUtpStream<I>, OutUtpStream<O>)>
where I: Send + Decodable + 'static, O: Send + Encodable + 'static {
    println!("utp_connections upgrade_utp {}", newconnection);
    // Configure a reading channel
    let (in_snd, in_rec) = mpsc::channel();
    // Create new private data for this
    let data = Box::new(EventCallback { in_snd : in_snd });
    // Set the private data on the socket
    unsafe { utp_crust_set_data(newconnection, Box::into_raw(data) as *mut ::libc::c_void) };
        
    Ok((InUtpStream::new(in_rec), OutUtpStream::new(newconnection)))
}

struct ReceiverAsStream {
    in_rec : Receiver<Vec<u8>>,
    remaining : Vec<u8>,
    offset : usize,
}

impl ReceiverAsStream {
    pub fn new(in_rec : Receiver<Vec<u8>>) -> ReceiverAsStream {
        ReceiverAsStream { in_rec : in_rec, remaining : Vec::new(), offset : 0 }
    }
}

impl Read for ReceiverAsStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            if !self.remaining.is_empty() {
                let mut bytestogo = self.remaining.len() - self.offset;
                println!("ReceiverAsStream::read() bytestogo={}, offset={}", bytestogo, self.offset);
                if bytestogo <= buf.len() {
                    for n in 0..bytestogo {
                        buf[n] = self.remaining[self.offset+n];
                    }
                    self.remaining.clear();
                    self.offset=0;
                    return Ok(bytestogo);
                }
                bytestogo = buf.len();
                for n in 0..bytestogo {
                    buf[n] = self.remaining[self.offset+n];
                }
                self.offset+=bytestogo;
                return Ok(bytestogo);
            }
            let newdata=self.in_rec.recv();
            if newdata.is_err() {
                return Err(Error::new(ErrorKind::ConnectionAborted, "Connection aborted"));
            }
            self.remaining=newdata.unwrap();
            println!("ReceiverAsStream::read() reads {} bytes", self.remaining.len());
        }
    }
}

pub struct InUtpStream<T>
where T: Decodable {
    buffer : BufReader<ReceiverAsStream>,
    _phantom: PhantomData<T>
}

pub struct InUtpStreamIter<'a, T: 'a>
where T: Decodable {
    stream : &'a mut InUtpStream<T>,
}

impl <'a, T> InUtpStream<T>
where T: Decodable {

    pub fn new(in_rec : Receiver<Vec<u8>>) -> InUtpStream<T> {
        InUtpStream { buffer : BufReader::new(ReceiverAsStream::new(in_rec)), _phantom: PhantomData }
    }
    
    pub fn recv(&mut self) -> Result<T> {
        println!("InUtpStream about to read");
        let mut decoder = Decoder::from_reader(&mut self.buffer);
        let result = decoder.decode().next();
        println!("InUtpStream read is_none={}", result.is_none());
        if result.is_none() {
            return Err(Error::new(ErrorKind::InvalidInput, "Unable to decode"));
        }
        let result = result.unwrap();
        println!("InUtpStream read is_err={}", result.is_err());
        if result.is_err() {
            return Err(Error::new(ErrorKind::InvalidInput, "Unable to decode"));
        }
        Ok(result.unwrap())
    }
    
    // I don't get why Rust thinks this unused code
    #[allow(dead_code)]
    pub fn iter(&'a mut self) -> InUtpStreamIter<'a, T> {
        InUtpStreamIter::<'a, T>::new(self)
    }
}

impl<'a, T> InUtpStreamIter<'a, T>
where T: Decodable {
    fn new(stream : &'a mut InUtpStream<T>) -> InUtpStreamIter<'a, T> { InUtpStreamIter { stream : stream } }
}

impl <'a, T> Iterator for InUtpStreamIter<'a, T>
where T: Decodable {
    type Item = T;
    
    fn next(&mut self) -> Option<T> {
        let ret = self.stream.recv();
        if ret.is_err() {
            None
        } else {
            Some(ret.unwrap())
        }
    }
}

pub struct OutUtpStream<T>
where T: Encodable {
    socket : utp_crust_socket,
    _phantom: PhantomData<T>
}

impl <T> OutUtpStream<T>
where T: Encodable {

    pub fn new(s: utp_crust_socket) -> OutUtpStream<T> {
        OutUtpStream { socket : s, _phantom: PhantomData }
    }
    
    pub fn send(&self, m: T) -> Result<()> {
        let mut encoder = Encoder::from_memory();
        let _ =encoder.encode(&[&m]);
        let encoded = encoder.as_bytes();
        println!("utp_connections: send to socket {} bytes {}", self.socket, encoded.len());
        if -1 == unsafe { utp_crust_send(self.socket, encoded.as_ptr() as *const libc::c_void, encoded.len() as libc::size_t) } {
            return Err(Error::last_os_error());
        }
        Ok(())
    }
    
    pub fn close(&mut self) -> Result<()> {
        if self.socket!=0 && -1 == unsafe { utp_crust_destroy_socket(self.socket, 1) } {
            return Err(Error::last_os_error());
        }
        self.socket=0;
        Ok(())
    }
}

impl <T> Drop for OutUtpStream<T>
where T: Encodable {
    fn drop(&mut self) {
        println!("OutUtpStream drops");
        let _ = self.close();
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::thread;
    use std::net::SocketAddr;
    use std::str::FromStr;

#[test]
#[ignore]
    fn test_small_stream() {
        let (event_receiver, port) = listen(5483).unwrap();
        let (mut i, mut o) = connect_utp(SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap()).unwrap();

        let read_thread = thread::spawn(move || {
            let (connection, _) = event_receiver.recv().unwrap();
            let (mut i, o) = upgrade_utp(connection).unwrap();
            for x in i.iter() {
                let x:u32 = x;
                println!("test_small_stream: new item {}", x);
                if o.send((x, x + 1)).is_err() { break; }
            }
        });
        for x in 0u64 .. 10u64 {
            if o.send(x).is_err() { break; }
        }
        // Collect everything that we get back.
        let mut responses: Vec<(u64, u64)> = Vec::new();
        for (a, b) in i.iter() {
            responses.push((a, b));
            if a == 9 {
                break;
            }
        }
        //println!("About to close");
        assert!(o.close().is_ok());
        //println!("About to join thread");
        assert!(read_thread.join().is_ok());
        // //println!("Responses: {:?}", responses);
        assert_eq!(10, responses.len());
    }

#[test]
#[ignore]
    fn test_multiple_nodes_small_stream() {
        const MSG_COUNT: usize = 5;
        const NODE_COUNT: usize = 101;

        let (event_receiver, port) = listen(5483).unwrap();                // one fd
        // event_receiver
        let _ = thread::spawn(move || {
            for x in event_receiver.iter() {                               // +101 fds
                let (connection, _) = x;
                // Spawn a new thread for each connection that we get.
                let _ = thread::spawn(move || {
                    let (mut i, o) = upgrade_utp(connection).unwrap();         // +303 fds
                    for x in i.iter() {
                        let x:u32 = x;
                        if o.send((x, x + 1)).is_err() { break; }
                    }
                });
            }
        });

        let mut vector_senders = Vec::new();
        let mut vector_receiver = Vec::new();
        for _ in 0..NODE_COUNT {
            let (i, o) = connect_utp(SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap()).unwrap(); // + 404 fds
            let boxed_output: Box<OutUtpStream<u64>> = Box::new(o);
            vector_senders.push(boxed_output);
            let boxed_input: Box<InUtpStream<(u64, u64)>> = Box::new(i);
            vector_receiver.push(boxed_input);
        }

        //  send
        for v in &mut vector_senders {
            for x in 0u64 .. MSG_COUNT as u64 {
                assert!(v.send(x).is_ok());
            }
        }

        // Collect everything that we get back.
        let mut responses: Vec<(u64, u64)> = Vec::new();

        //println!("Collecting responses ...");
        loop {
           let _ = match vector_receiver.pop() {
                None => break, // empty
                Some(mut receiver) => {
                    for (a, b) in receiver.iter() {
                        responses.push((a, b));
                        if a == MSG_COUNT as u64 - 1 {
                            break;
                        }
                    }
                }
            };
        }

        //  close sender
        //println!("Closing senders ...");
        loop {
           let _ = match vector_senders.pop() {
                None => break, // empty
                Some(mut sender) => sender.close(),
            };
        }

        // //println!("Responses: {:?}", responses);
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
