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

use utp::UtpSocket;
pub use utp_wrapper::UtpWrapper;
use std::net::UdpSocket;
use socket_addr::SocketAddr;
use std::io::Result as IoResult;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::io;
use std::time::Duration;
use maidsafe_utilities::serialisation::{deserialise, serialise};

use periodic_sender::PeriodicSender;
use event::WriteEvent;
use listener_message::{ListenerRequest, ListenerResponse};
use hole_punching::HolePunch;
use socket_utils::RecvUntil;

/// Connect to a peer and open a send-receive pair.  See `upgrade` for more details.
pub fn connect_utp(addr: SocketAddr) -> IoResult<(UtpWrapper, Sender<WriteEvent>)> {
    upgrade_utp(try!(UtpSocket::connect(&*addr)))
}

pub fn rendezvous_connect_utp(udp_socket: UdpSocket,
                              addr: SocketAddr)
                              -> IoResult<(UtpWrapper, Sender<WriteEvent>)> {
    upgrade_utp(try!(UtpSocket::rendezvous_connect(udp_socket, &*addr)))
}

/// Upgrades a newly connected UtpSocket to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.  If there is an error decoding or encoding
/// values, that respective part is shut down.
pub fn upgrade_utp(newconnection: UtpSocket) -> IoResult<(UtpWrapper, Sender<WriteEvent>)> {
    let (output_tx, output_rx) = mpsc::channel();
    let wrapper = try!(UtpWrapper::wrap(newconnection, output_rx));

    Ok((wrapper, output_tx))
}

// TODO(canndrew): This should return a Vec of SocketAddrs rather than a single SocketAddr. The Vec
// should contain all known addresses of the socket.
pub fn external_udp_socket(peer_udp_listeners: Vec<SocketAddr>)
                           -> io::Result<(UdpSocket, Vec<SocketAddr>)> {
    const MAX_DATAGRAM_SIZE: usize = 256;

    let udp_socket = try!(UdpSocket::bind("0.0.0.0:0"));
    let port = try!(udp_socket.local_addr()).port();
    try!(udp_socket.set_read_timeout(Some(Duration::from_secs(2))));
    let cloned_udp_socket = try!(udp_socket.try_clone());

    let send_data = unwrap_result!(serialise(&ListenerRequest::EchoExternalAddr));

    let if_addrs = try!(get_if_addrs::get_if_addrs())
                       .into_iter()
                       .map(|i| SocketAddr::new(i.addr.ip(), port))
                       .collect_vec();

    let res = try!(::crossbeam::scope(|scope| -> io::Result<SocketAddr> {
        // TODO Instead of periodic sender just send the request to every body and start listening.
        // If we get it back from even one, we collect the info and return.
        for udp_listener in &peer_udp_listeners {
            let cloned_udp_socket = try!(cloned_udp_socket.try_clone());
            let _periodic_sender = PeriodicSender::start(cloned_udp_socket,
                                                         *udp_listener,
                                                         scope,
                                                         &send_data[..],
                                                         ::std::time::Duration::from_millis(300));
            let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];
            let (read_size, recv_addr) = match udp_socket.recv_from(&mut recv_data[..]) {
                Ok(res) => res,
                Err(_) => continue,
            };

            if let Ok(ListenerResponse::EchoExternalAddr { external_addr }) =
                   deserialise::<ListenerResponse>(&recv_data[..read_size]) {
                let mut addrs = vec![external_addr];
                addrs.extend(if_addrs);
                return Ok(addrs);
            }
        }
        return if_addrs;
    }));

    Ok((udp_socket, res))
}

// TODO All this function should be returning is either an Ok(()) or Err(..)
/// Returns the socket along with the peer's SocketAddr
pub fn blocking_udp_punch_hole(udp_socket: UdpSocket,
                               secret: Option<[u8; 4]>,
                               peer_addr: SocketAddr)
                               -> (UdpSocket, io::Result<SocketAddr>) {
    // Cbor seems to serialize into bytes of different sizes and
    // it sometimes exceeded 16 bytes, let's be safe and use 128.
    const MAX_DATAGRAM_SIZE: usize = 128;

    let send_data = {
        let hole_punch = HolePunch {
            secret: secret,
            ack: false,
        };
        let mut enc = ::cbor::Encoder::from_memory();
        enc.encode(::std::iter::once(&hole_punch)).unwrap();
        enc.into_bytes()
    };

    assert!(send_data.len() <= MAX_DATAGRAM_SIZE,
            format!("Data exceed MAX_DATAGRAM_SIZE in blocking_udp_punch_hole: {} > {}",
                    send_data.len(),
                    MAX_DATAGRAM_SIZE));

    let addr_res: io::Result<SocketAddr> = ::crossbeam::scope(|scope| {
        let sender = try!(udp_socket.try_clone());
        let receiver = try!(udp_socket.try_clone());
        let periodic_sender = PeriodicSender::start(sender,
                                                    peer_addr,
                                                    scope,
                                                    send_data,
                                                    ::std::time::Duration::from_millis(500));

        let addr_res: io::Result<Option<SocketAddr>> =
            (|| {
                let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];
                let mut peer_addr: Option<SocketAddr> = None;
                let deadline = ::time::SteadyTime::now() + ::time::Duration::seconds(2);
                loop {
                    let (read_size, addr) = match try!(receiver.recv_until(&mut recv_data[..],
                                                                           deadline)) {
                        Some(x) => x,
                        None => {
                            return Ok(peer_addr);
                        }
                    };

                    match ::cbor::Decoder::from_reader(&recv_data[..read_size])
                              .decode::<HolePunch>()
                              .next() {
                        Some(Ok(ref hp)) => {
                            if hp.secret == secret {
                                if hp.ack {
                                    return Ok(Some(addr));
                                } else {
                                    let send_data = {
                                        let hole_punch = HolePunch {
                                            secret: secret,
                                            ack: true,
                                        };
                                        let mut enc = ::cbor::Encoder::from_memory();
                                        enc.encode(::std::iter::once(&hole_punch)).unwrap();
                                        enc.into_bytes()
                                    };
                                    periodic_sender.set_payload(send_data);
                                    periodic_sender.set_destination(addr);
                                    // TODO Do not do this. The only thing we should do is make
                                    // sure the supplied peer_addr to this function is == to this
                                    // addr (which can be spoofed anyway so additionally verify the
                                    // secret above), otherwise it would mean we are connecting to
                                    // someone who we are not sending HolePunch struct to
                                    peer_addr = Some(addr);
                                }
                            } else {
                                info!("udp_hole_punch non matching secret");
                            }
                        }
                        x => {
                            info!("udp_hole_punch received invalid data: {:?}", x);
                        }
                    };
                }
            })();
        match addr_res {
            Err(e) => Err(e),
            Ok(Some(x)) => Ok(x),
            Ok(None) => {
                Err(io::Error::new(io::ErrorKind::TimedOut,
                                   "Timed out waiting for rendevous connection"))
            }
        }
    });

    (udp_socket, addr_res)
}

#[allow(unused)]
mod test {
    use super::*;
    use std::thread;
    use socket_addr::{SocketAddr, SocketAddrV4};
    use std::net::{Ipv4Addr, UdpSocket};
    use std::net;
    use std::io::Read;
    use utp::UtpListener;
    use event::WriteEvent;
    use std::io;
    use std::thread::spawn;
    use std::sync::Arc;

    fn listen(port: u16) -> io::Result<UtpListener> {
        UtpListener::bind(("0.0.0.0", port))
    }

    #[test]
    fn cannot_establish_connection() {
        let listener = UdpSocket::bind({
                           net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0)
                       })
                           .unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let _err =
            connect_utp(SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(Ipv4Addr::new(127,
                                                                                       0,
                                                                                       0,
                                                                                       1),
                                                                         port))))
                .err()
                .unwrap();
    }

    #[test]
    fn establishing_connection() {
        let listener = listen(0).unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = spawn(move || listener.accept().unwrap());

        // Note: when the result of connect_utp here is assigned to a variable
        // named _, this test takes much longet to complete. My guess is that
        // it happens because _ is dropped immediately, but any other named
        // variable is dropped only at the end of the scope. So when naming
        // this variable, the socket outlives the above thread, which somehow
        // makes this test finish faster for some reason.
        let _socket = connect_utp(SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(Ipv4Addr::new(127,
                                                                                                      0,
                                                                                                      0,
                                                                                                      1),
                                                                                        port))))
                    .unwrap();

        let _ = handle.join().unwrap();
    }

    #[test]
    fn send_receive_data() {
        let listener = listen(0).unwrap();
        let port = listener.local_addr().unwrap().port();

        let th0 = spawn(move || {
            let s = listener.accept().unwrap().0;
            let (mut i, o) = upgrade_utp(s).unwrap();
            let mut buf = [0u8; 1];
            let _ = i.read(&mut buf).unwrap();
            assert_eq!(buf[0], 42);
            o.send(WriteEvent::Write(vec![43]));
        });

        let (mut i, o) =
            connect_utp(SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(Ipv4Addr::new(127,
                                                                                       0,
                                                                                       0,
                                                                                       1),
                                                                         port))))
                .unwrap();

        let th1 = spawn(move || {
            o.send(WriteEvent::Write(vec![42]));
            let mut buf = [0u8; 1];
            let _ = i.read(&mut buf).unwrap();
            assert_eq!(buf[0], 43);
        });

        th1.join();
        th0.join();
    }

    fn loopback_v4(port: u16) -> SocketAddr {
        SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)))
    }

    fn run_hole_punching(socket: UdpSocket,
                         peer_addr: SocketAddr,
                         secret: Option<[u8; 4]>)
                         -> io::Result<SocketAddr> {
        blocking_udp_punch_hole(socket, secret, peer_addr).1
    }

    fn duration_diff(t1: ::time::Duration, t2: ::time::Duration) -> ::time::Duration {
        if t1 >= t2 {
            t1 - t2
        } else {
            t2 - t1
        }
    }

    // On Windows, setting UdpSocket::set_read_timeout(X) causes
    // the UdpSocket::recv_from function to wait (X + E) where E
    // is ~500ms. We calculate this E here to adjust our tests.
    // See here for more info:
    // https://users.rust-lang.org/t/on-windows-udpsocket-set-read-timeout-x-waits-x-500ms/3334
    fn read_timeout_error() -> ::time::Duration {
        let mut buf = [0u8; 32];
        let s = UdpSocket::bind(&*loopback_v4(0)).unwrap();

        ::time::Duration::span(|| {
            let timeout = ::std::time::Duration::from_millis(1);
            s.set_read_timeout(Some(timeout)).unwrap();
            let _ = s.recv_from(&mut buf);
        })
    }

    // Note: numbers in function names are used to specify order in
    //       which they should be run.

    #[test]
    fn test_udp_hole_punching_0_time_out() {
        let timeout = ::time::Duration::seconds(2);

        let s1 = UdpSocket::bind(&*loopback_v4(0)).unwrap();
        let s2 = UdpSocket::bind(&*loopback_v4(0)).unwrap();

        let s2_addr = loopback_v4(s2.local_addr().unwrap().port());
        let start = ::time::SteadyTime::now();

        let t = spawn(move || run_hole_punching(s1, s2_addr, None));

        let thread_status = t.join();
        assert!(thread_status.is_ok());

        let end = ::time::SteadyTime::now();

        let duration = if !cfg!(windows) {
            end - start
        } else {
            end - start - read_timeout_error()
        };

        let diff = duration_diff(duration, timeout);
        assert!(diff < ::time::Duration::milliseconds(200));

        let punch_status = thread_status.unwrap();
        assert_eq!(punch_status.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn test_udp_hole_punching_1_terminates_no_secret() {
        let s1 = UdpSocket::bind(&*loopback_v4(0)).unwrap();
        let s2 = UdpSocket::bind(&*loopback_v4(0)).unwrap();

        let s1_addr = loopback_v4(s1.local_addr().unwrap().port());
        let s2_addr = loopback_v4(s2.local_addr().unwrap().port());

        let t1 = spawn(move || run_hole_punching(s1, s2_addr, None));
        let t2 = spawn(move || run_hole_punching(s2, s1_addr, None));

        let r1 = t1.join();
        let r2 = t2.join();

        let _ = r1.unwrap().unwrap();
        let _ = r2.unwrap().unwrap();
    }

    #[test]
    fn test_udp_hole_punching_2_terminates_with_secret() {
        let s1 = UdpSocket::bind(&*loopback_v4(0)).unwrap();
        let s2 = UdpSocket::bind(&*loopback_v4(0)).unwrap();

        let s1_addr = loopback_v4(s1.local_addr().unwrap().port());
        let s2_addr = loopback_v4(s2.local_addr().unwrap().port());

        let secret = ::rand::random();

        let t1 = spawn(move || run_hole_punching(s1, s2_addr, secret));
        let t2 = spawn(move || run_hole_punching(s2, s1_addr, secret));

        let r1 = t1.join();
        let r2 = t2.join();

        let _ = r1.unwrap().unwrap();
        let _ = r2.unwrap().unwrap();
    }
}
