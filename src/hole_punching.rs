use std::net::UdpSocket;
use std::io;
use std::io::{Error, ErrorKind};
use std::net;
use std::sync::{Arc, RwLock};
use std::sync::mpsc::Sender;
use std::sync::atomic::{Ordering, AtomicBool};
use std::time::Duration;

use periodic_sender::PeriodicSender;
use socket_utils::RecvUntil;
use endpoint::{Protocol, Endpoint};
use socket_addr::{SocketAddr, SocketAddrV4};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use udp_listener::{EchoExternalAddrResp, UdpListenerMsg};

#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct HolePunch {
    pub secret: Option<[u8; 4]>,
    pub ack: bool,
}

// TODO(canndrew): This should return a Vec of SocketAddrs rather than a single SocketAddr. The Vec
// should contain all known addresses of the socket.
pub fn external_udp_socket(request_id: u32,
                           udp_listeners: Vec<SocketAddr>)
                           -> io::Result<(UdpSocket, SocketAddr)> {
    const MAX_DATAGRAM_SIZE: usize = 256;

    let udp_socket = try!(UdpSocket::bind("0.0.0.0:0"));
    try!(udp_socket.set_read_timeout(Some(Duration::from_secs(2))));
    let cloned_udp_socket = try!(udp_socket.try_clone());

    let send_data = unwrap_result!(serialise(&UdpListenerMsg::EchoExternalAddr));

    let res = try!(::crossbeam::scope(|scope| -> io::Result<SocketAddr> {
        // TODO Instead of periodic sender just send the request to every body and start listening.
        // If we get it back from even one, we collect the info and return.
        for udp_listener in &udp_listeners {
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

            if let Ok(EchoExternalAddrResp { external_addr }) =
                   deserialise::<EchoExternalAddrResp>(&recv_data[..read_size]) {
                return Ok(external_addr);
            }
        }
        return Err(Error::new(ErrorKind::Other, "TODO - Improve this - Could Not find our external address"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net;
    use std::net::{UdpSocket, Ipv4Addr};
    use std::thread::spawn;
    use socket_addr::SocketAddr;
    use std::sync::Arc;

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
