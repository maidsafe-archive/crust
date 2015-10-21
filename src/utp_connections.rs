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
pub use utp_wrapper::UtpWrapper;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr, UdpSocket};
use std::io::Result as IoResult;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;

/// Connect to a peer and open a send-receive pair.  See `upgrade` for more details.
pub fn connect_utp(addr: SocketAddr)
                   -> IoResult<(UtpWrapper, Sender<Vec<u8>>)> {
    upgrade_utp(try!(UtpSocket::connect(addr)))
}

pub fn rendezvous_connect_utp(udp_socket: UdpSocket, addr: SocketAddr)
                              -> IoResult<(UtpWrapper, Sender<Vec<u8>>)> {
    upgrade_utp(try!(UtpSocket::rendezvous_connect(udp_socket, addr)))
}

/// Starts listening for connections on this ip and port.
/// Returns:
/// * A receiver of Utp socket objects.  It is recommended that you `upgrade` these.
/// * Port
pub fn listen(port: u16) -> IoResult<(Receiver<(UtpSocket, SocketAddr)>, SocketAddr)> {
    let listener = try!(UtpListener::bind(SocketAddr::V4({
        SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port)
    })));
    let local_addr = try!(listener.local_addr());
    let (tx, rx) = mpsc::channel();
    let _ = thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok(s) => if tx.send(s).is_err() { break },
                Err(_) => break,
            }
        }
    });
    Ok((rx, local_addr))
}

/// Upgrades a newly connected UtpSocket to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.  If there is an error decoding or encoding
/// values, that respective part is shut down.
pub fn upgrade_utp(newconnection: UtpSocket)
                   -> IoResult<(UtpWrapper, Sender<Vec<u8>>)> {
    let socket = try!(UtpWrapper::wrap(newconnection));
    let output = socket.output();
    Ok((socket, output))
}

#[allow(unused)]
mod test {
    use super::*;
    use std::thread;
    use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr, UdpSocket};
    use std::io::Read;

    #[test]
    fn cannot_establish_connection() {
        let listener = UdpSocket::bind({
            SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0)
        }).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let _err = connect_utp(SocketAddr::V4({
            SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)
        })).err().unwrap();
    }

    #[test]
    fn establishing_connection() {
        let listener = listen(0).unwrap();
        let _ = connect_utp(SocketAddr::V4({
            SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), listener.1.port())
        })).unwrap();
    }

    #[test]
    fn send_receive_data() {
        let listener = listen(0).unwrap();
        let (mut i, o) = connect_utp(SocketAddr::V4({
            SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), listener.1.port())
        })).unwrap();
        let listener = listener.0;
        let thread = thread::spawn(move || {
            o.send(vec![42]);
            let mut buf = [0u8; 1];
            let _ = i.read(&mut buf).unwrap();
            assert_eq!(buf[0], 43);
        });
        let s = listener.recv().unwrap().0;
        let (mut i, o) = upgrade_utp(s).unwrap();
        let mut buf = [0u8; 1];
        let _ = i.read(&mut buf).unwrap();
        assert_eq!(buf[0], 42);
        o.send(vec![43]);
        thread.join();
    }
}
