use std::net::{SocketAddr, UdpSocket, SocketAddrV4};
use std::io;
use std::sync::{Arc, RwLock};
use std::sync::mpsc::Sender;

use periodic_sender::PeriodicSender;
use socket_utils::RecvUntil;
use auxip::Endpoint;
use state::{Closure, State};
use transport::Message;
use util::{SocketAddrW, SocketAddrV4W};

#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct HolePunch {
    pub secret: Option<[u8; 4]>,
    pub ack: bool,
}

#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct GetExternalAddr {
    pub magic: u32,
    pub request_id: u32,
}

// TODO (canndrew): this should be an associated constant once they're stabilised
const GET_EXTERNAL_ADDR_MAGIC: u32 = 0x5d45cb20;

impl GetExternalAddr {
    fn new(request_id: u32) -> GetExternalAddr {
        GetExternalAddr {
            magic: GET_EXTERNAL_ADDR_MAGIC,
            request_id: request_id,
        }
    }
}

#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct SetExternalAddr {
    pub request_id: u32,
    pub addr: SocketAddrW,
}

pub fn blocking_get_mapped_udp_socket(request_id: u32, helper_nodes: Vec<SocketAddr>)
        -> io::Result<(UdpSocket, Option<SocketAddr>, Vec<SocketAddr>)>
{
    const MAX_DATAGRAM_SIZE: usize = 256;

    let udp_socket = try!(UdpSocket::bind("0.0.0.0:0"));
    let receiver = try!(udp_socket.try_clone());

    let send_data = {
        let gea = GetExternalAddr::new(request_id);
        let mut enc = ::cbor::Encoder::from_memory();
        enc.encode(::std::iter::once(&gea)).unwrap();
        enc.into_bytes()
    };

    let res = try!(::crossbeam::scope(|scope| -> io::Result<Option<(SocketAddr, usize)>> {
        for helper in helper_nodes.iter() {
            let sender = try!(udp_socket.try_clone());
            let _periodic_sender = PeriodicSender::start(sender, *helper, scope, &send_data[..], ::std::time::Duration::from_millis(300));
            let deadline = ::time::SteadyTime::now() + ::time::Duration::seconds(2);
            let res = try!((|| -> io::Result<Option<(SocketAddr, usize)>> {
                loop {
                    let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];
                    let (read_size, recv_addr) = match try!(receiver.recv_until(&mut recv_data[..], deadline)) {
                        Some(x) => x,
                        None    => return Ok(None),
                    };
                    match helper_nodes.iter().position(|&a| a == recv_addr) {
                        None    => continue,
                        Some(i) => match ::cbor::Decoder::from_reader(&recv_data[..read_size])
                                                         .decode::<SetExternalAddr>().next() {
                            Some(Ok(sea)) => {
                                if sea.request_id != request_id {
                                    continue;
                                }
                                return Ok(Some((sea.addr.0, i)))
                            }
                            x   => {
                                info!("Received invalid reply from udp hole punch server: {:?}", x);
                                continue;
                            }
                        }
                    }
                }
            })());
            match res {
                Some(x) => return Ok(Some(x)),
                None    => continue,
            }
        }
        Ok(None)
    }));
    match res {
        None => Ok((udp_socket, None, Vec::new())),
        Some((our_addr, responder_index))
            => Ok((udp_socket, Some(our_addr), helper_nodes.into_iter()
                                                           .skip(responder_index + 1)
                                                           .collect::<Vec<SocketAddr>>())),
    }
}

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
        let sender          = try!(udp_socket.try_clone());
        let receiver        = try!(udp_socket.try_clone());
        let periodic_sender = PeriodicSender::start(sender,
                                                    peer_addr,
                                                    scope,
                                                    send_data,
                                                    ::std::time::Duration::from_millis(500));

        let addr_res: io::Result<Option<SocketAddr>> = (|| {
            let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];
            let mut peer_addr: Option<SocketAddr> = None;
            let deadline = ::time::SteadyTime::now() + ::time::Duration::seconds(2);
            loop {
                let (read_size, addr) = match try!(receiver.recv_until(&mut recv_data[..], deadline)) {
                    Some(x) => x,
                    None => return Ok(peer_addr),
                };

                match ::cbor::Decoder::from_reader(&recv_data[..read_size])
                                      .decode::<HolePunch>().next() {
                    Some(Ok(ref hp)) => {
                        if hp.secret == secret {
                            if hp.ack {
                                return Ok(Some(addr))
                            }
                            else {
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
                                peer_addr = Some(addr);
                            }
                        }
                        else {
                            info!("udp_hole_punch non matching secret");
                        }
                    },
                    x   => info!("udp_hole_punch received invalid data: {:?}", x),
                };
            }
        })();
        match addr_res {
            Err(e)      => Err(e),
            Ok(Some(x)) => Ok(x),
            Ok(None)    => Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out waiting for rendevous connection")),
        }
    });

    (udp_socket, addr_res)
}

/// RAII type for udp hole punching server.
pub struct HolePunchServer {
    listener_shutdown: ::std::sync::mpsc::Sender<()>,
    upnp_shutdown: ::std::sync::mpsc::Sender<()>,

    // TODO (canndrew): Ideally this should not need to be an Option<> as the server thread should
    // have the same lifetime as the Server object. Can change this once rust has linear types.
    listener_handle: Option<::std::thread::JoinHandle<io::Result<()>>>,
    upnp_handle: Option<::std::thread::JoinHandle<()>>,
    internal_addr: SocketAddrV4,
    external_addr: Arc<RwLock<Option<SocketAddrV4>>>,
}

impl HolePunchServer {
    /// Create a new hole punching server.
    pub fn start(cmd_sender: Sender<Closure>) -> io::Result<HolePunchServer> {
        const MAX_DATAGRAM_SIZE: usize = 256;

        // Refresh the hole punched for our server socket every hour.
        // TODO: make this a Duration once Duration has a const constructor
        const UPNP_REFRESH_PERIOD_MS: u64 = 1000 * 60 * 60;

        let (listener_tx, listener_rx) = ::std::sync::mpsc::channel::<()>();
        let udp_socket = try!(UdpSocket::bind("0.0.0.0:0"));
        let local_addr = match try!(udp_socket.local_addr()) {
            SocketAddr::V4(sa)  => sa,
            SocketAddr::V6(_)   => return Err(io::Error::new(io::ErrorKind::Other, "bind(\"0.0.0.0:0\") returned an ipv6 socket")),
        };
        let hole_punch_listener = try!(::std::thread::Builder::new().name(String::from("udp hole punch server"))
                                                                    .spawn(move || {
            loop {
                match listener_rx.try_recv() {
                    Err(::std::sync::mpsc::TryRecvError::Empty)        => (),
                    Err(::std::sync::mpsc::TryRecvError::Disconnected) => panic!(),
                    Ok(())  => return Ok(()),
                }
                let mut data_recv = [0u8; MAX_DATAGRAM_SIZE];
                /*
                 * TODO (canndrew):
                 * Currently we set a read timeout so that the hole punch server thread continually wakes
                 * and checks to see if it's time to exit. This is a really crappy way of implementing
                 * this but currently rust doesn't have a good cross-platform select/epoll interface.
                 */
                let deadline = ::time::SteadyTime::now() + ::time::Duration::seconds(1);
                let (read_size, addr) = match try!(udp_socket.recv_until(&mut data_recv[..], deadline)) {
                    Some(x) => x,
                    None    => continue,
                };
                match ::cbor::Decoder::from_reader(&data_recv[..read_size])
                                     .decode::<GetExternalAddr>().next() {
                    Some(Ok(gea)) => {
                        if gea.magic != GET_EXTERNAL_ADDR_MAGIC {
                            continue;
                        }
                        let data_send = {
                            let sea = SetExternalAddr {
                                request_id: gea.request_id,
                                addr: SocketAddrW(addr),
                            };
                            let mut enc = ::cbor::Encoder::from_memory();
                            enc.encode(::std::iter::once(&sea)).unwrap();
                            enc.into_bytes()
                        };
                        let send_size = try!(udp_socket.send_to(&data_send[..], addr));
                        if send_size != data_send.len() {
                            warn!("Failed to send entire SetExternalAddr message. {} < {}", send_size, data_send.len());
                        }
                    }
                    x => info!("Hole punch server received invalid GetExternalAddr: {:?}", x),
                };
            }
        }));

        let external_ip = Arc::new(RwLock::new(None::<SocketAddrV4>));
        let external_ip_writer = external_ip.clone();
        let local_ep = Endpoint::Udp(SocketAddr::V4(local_addr.clone()));
        let (upnp_tx, upnp_rx) = ::std::sync::mpsc::channel::<()>();
        let upnp_hole_puncher = try!(::std::thread::Builder::new().name(String::from("upnp hole puncher"))
                                                                  .spawn(move || {
            loop {
                match upnp_rx.try_recv() {
                    Err(::std::sync::mpsc::TryRecvError::Empty)        => (),
                    Err(::std::sync::mpsc::TryRecvError::Disconnected) => panic!(),
                    Ok(())  => return (),
                }
                match ::map_external_port::sync_map_external_port(&local_ep) {
                    Ok(v)   => {
                        for (internal, external) in v {
                            if internal == local_addr {
                                match external {
                                    Endpoint::Udp(SocketAddr::V4(sa))   => {
                                        {
                                            let mut ext_ip = external_ip_writer.write().unwrap();
                                            *ext_ip = Some(sa);
                                        };
                                        let _ = cmd_sender.send(Closure::new(move |state: &mut State| {
                                            for cd in state.connections.values() {
                                                let _ = cd.message_sender.send(Message::HolePunchAddress(SocketAddrV4W(sa)));
                                            }
                                        }));
                                    },

                                    // TODO (canndrew): improve the igd APIs to make this panic
                                    // unnecessary.
                                    _                                   => panic!(),
                                }
                            }
                        }
                    }
                    Err(e)  => info!("Failed to get external IP using upnp: {:?}", e),
                }
                // TODO (canndrew): What is a sensible time to wait between refreshes of our
                // external ip?
                ::std::thread::park_timeout(::std::time::Duration::from_millis(UPNP_REFRESH_PERIOD_MS));
            }
        }));
        Ok(HolePunchServer {
            listener_shutdown: listener_tx,
            upnp_shutdown: upnp_tx,
            listener_handle: Some(hole_punch_listener),
            upnp_handle: Some(upnp_hole_puncher),
            internal_addr: local_addr,
            external_addr: external_ip,
        })
    }

    /// Get the address that this server is listening on.
    pub fn listening_addr(&self) -> SocketAddrV4 {
        self.internal_addr
    }

    /// Get the external address of the server (if it is known)
    pub fn external_address(&self) -> Option<SocketAddrV4> {
        let guard = self.external_addr.read().unwrap();
        *guard
    }
}

impl Drop for HolePunchServer {
    fn drop(&mut self) {
        // Ignore this error. If the server thread has exited we'll find out about it when we
        // join the JoinHandle.
        let _ = self.listener_shutdown.send(());
        let _ = self.upnp_shutdown.send(());

        if let Some(listener_handle) = self.listener_handle.take() {
            match listener_handle.join() {
                Ok(Ok(()))  => (),
                Ok(Err(e))  => warn!("The udp hole punch server exited due to IO error: {}", e),
                Err(e)      => error!("The udp hole punch server panicked!: {:?}", e),
            }
        };

        if let Some(upnp_handle) = self.upnp_handle.take() {
            upnp_handle.thread().unpark();
            match upnp_handle.join() {
                Ok(())  => (),
                Err(e)  => error!("The upnp hole puncher panicked!: {:?}", e),
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::{UdpSocket, SocketAddr, SocketAddrV4, Ipv4Addr};
    use std::thread::spawn;

    fn loopback_v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), port))
    }

    fn run_hole_punching(socket:    UdpSocket,
                         peer_addr: SocketAddr,
                         secret:    Option<[u8; 4]>)
            -> io::Result<SocketAddr> {
        blocking_udp_punch_hole(socket, secret, peer_addr).1
    }

    fn duration_diff(t1: ::time::Duration, t2: ::time::Duration) -> ::time::Duration {
        if t1 >= t2 { t1 - t2 } else { t2 - t1 }
    }

    // On Windows, setting UdpSocket::set_read_timeout(X) causes
    // the UdpSocket::recv_from function to wait (X + E) where E
    // is ~500ms. We calculate this E here to adjust our tests.
    // See here for more info:
    // https://users.rust-lang.org/t/on-windows-udpsocket-set-read-timeout-x-waits-x-500ms/3334
    fn read_timeout_error() -> ::time::Duration {
        let mut buf = [0u8; 32];
        let s = UdpSocket::bind(loopback_v4(0)).unwrap();

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

        let s1 = UdpSocket::bind(loopback_v4(0)).unwrap();
        let s2 = UdpSocket::bind(loopback_v4(0)).unwrap();

        let s2_addr = loopback_v4(s2.local_addr().unwrap().port());
        let start = ::time::SteadyTime::now();

        let t = spawn(move || run_hole_punching(s1, s2_addr, None));

        let thread_status = t.join();
        assert!(thread_status.is_ok());

        let end = ::time::SteadyTime::now();

        let duration = if !cfg!(windows) {
            end - start
        }
        else {
            end - start - read_timeout_error()
        };

        let diff = duration_diff(duration, timeout);
        assert!(diff < ::time::Duration::milliseconds(200));

        let punch_status = thread_status.unwrap();
        assert_eq!(punch_status.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn test_udp_hole_punching_1_terminates_no_secret() {
        let s1 = UdpSocket::bind(loopback_v4(0)).unwrap();
        let s2 = UdpSocket::bind(loopback_v4(0)).unwrap();

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
        let s1 = UdpSocket::bind(loopback_v4(0)).unwrap();
        let s2 = UdpSocket::bind(loopback_v4(0)).unwrap();

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

    #[test]
    fn test_get_mapped_socket_from_self() {
        let (category_tx, _) = ::std::sync::mpsc::channel();
        let (tx, _rx) = ::std::sync::mpsc::channel();

        let crust_event_category = ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent;
        let event_sender = ::maidsafe_utilities::event_sender::MaidSafeObserver::new(tx,
                                                                                     crust_event_category,
                                                                                     category_tx);
        let mut state = ::state::State::new(event_sender).unwrap();
        let (socket, our_addr, remaining)
            = blocking_get_mapped_udp_socket(::rand::random(),
                                             vec![loopback_v4(state.mapper.listening_addr().port())]).unwrap();

        let received_addr = our_addr.unwrap();
        let socket_addr = socket.local_addr().unwrap();
        assert_eq!(loopback_v4(socket_addr.port()), received_addr);
        assert!(remaining.is_empty());
        state.stop();
    }
}
