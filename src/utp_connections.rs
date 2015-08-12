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

use utp::{UtpSocket, UtpListener};
use utp_wrapper::UtpWrapper;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::io::Result as IoResult;
use rustc_serialize::{Decodable, Encodable};
use cbor::{Encoder, Decoder};
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;

pub type UtpReader<T> = Receiver<T>;
pub type UtpWriter<T> = Sender<T>;

pub type InUtpStream<T> = Receiver<T>;
pub type OutUtpStream<T> = Sender<T>;

/// Connect to a peer and open a send-receive pair.  See `upgrade` for more details.
pub fn connect_utp<'a, 'b, I, O>(addr: SocketAddr) -> IoResult<(Receiver<I>, Sender<O>)>
        where I: Send + Decodable + 'static, O: Send + Encodable + 'static {
    upgrade_utp(try!(UtpSocket::connect(addr)))
}

/// Starts listening for connections on this ip and port.
/// Returns:
/// * A receiver of Utp socket objects.  It is recommended that you `upgrade` these.
/// * Port
pub fn listen(port: u16) -> IoResult<(Receiver<(UtpSocket, SocketAddr)>, u16)> {
    let listener = try!(UtpListener::bind(SocketAddr::V4({
        SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port)
    })));
    let port = try!(listener.local_addr()).port();
    let (tx, rx) = mpsc::channel();
    let _ = thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok(s) => if tx.send(s).is_err() { break },
                Err(_) => break,
            }
        }
    });
    Ok((rx, port))
}

/// Upgrades a newly connected UtpSocket to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.  If there is an error decoding or encoding
/// values, that respective part is shut down.
pub fn upgrade_utp<'a, 'b, I, O>(newconnection: UtpSocket)
                                 -> IoResult<(Receiver<I>, Sender<O>)>
where I: Send + Decodable + 'static, O: Send + Encodable + 'static {
    let socket = UtpWrapper::wrap(newconnection);
    let output = socket.output();
    Ok((upgrade_reader(socket), upgrade_writer(output)))
}

fn upgrade_writer<'a, T>(sender: Sender<Vec<u8>>) -> Sender<T>
    where T: Send + Encodable + 'static {
    let (tx, rx) = mpsc::channel();
    let _ = thread::spawn(move || {
        let mut e = Encoder::from_memory();
        while let Ok(v) = rx.recv() {
            e.encode(&vec![v]).unwrap();
            if sender.send(Vec::from(e.as_bytes())).is_err() {
                break;
            }
        }
    });
    tx
}

fn upgrade_reader<'a, T>(socket: UtpWrapper) -> Receiver<T>
    where T: Send + Decodable + 'static {
    let (tx, rx) = mpsc::channel();
    let _ = thread::spawn(move || {
        let mut decoder = Decoder::from_reader(socket);
        loop {
            let data = match decoder.decode().next() {
                Some(a) => a,
                None => break,
            };
            match data {
                Ok(data) => {
                    if tx.send(data).is_err() {
                        break
                    }
                },
                Err(_) => break,
            }
        }
    });
    rx
}
