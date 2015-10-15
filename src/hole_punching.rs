use std::net::{SocketAddr, UdpSocket};
use std::io;
use std::str::FromStr;

use periodic_sender::PeriodicSender;

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
    pub addr: WrapSocketAddr,
}

#[derive(Debug)]
pub struct WrapSocketAddr(pub SocketAddr);

impl ::rustc_serialize::Encodable for WrapSocketAddr {
    fn encode<S: ::rustc_serialize::Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let as_string = format!("{}", self.0);
        try!(s.emit_str(&as_string[..]));
        Ok(())
    }
}

impl ::rustc_serialize::Decodable for WrapSocketAddr {
    fn decode<D: ::rustc_serialize::Decoder>(d: &mut D) -> Result<WrapSocketAddr, D::Error> {
        let as_string = try!(d.read_str());
        match SocketAddr::from_str(&as_string[..]) {
            Ok(sa)  => Ok(WrapSocketAddr(sa)),
            Err(e)  => {
                let err = format!("Failed to decode WrapSocketAddr: {}", e);
                Err(d.error(&err[..]))
            }
        }
    }
}

pub fn blocking_get_mapped_udp_socket(request_id: u32, helper_nodes: Vec<SocketAddr>)
        -> io::Result<(UdpSocket, Option<SocketAddr>, Vec<SocketAddr>)>
{
    let timeout = ::time::Duration::seconds(2);

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
            let periodic_sender = PeriodicSender::start(sender, ::std::slice::ref_slice(helper), scope, &send_data[..], 300);
            let start_time = ::time::now();
            let res = try!((|| -> io::Result<Option<(SocketAddr, usize)>> {
                loop {
                    let current_time = ::time::now();
                    let time_spent = current_time - start_time;
                    let timeout_remaining = timeout - time_spent;
                    if timeout_remaining <= ::time::Duration::zero() {
                        return Ok(None);
                    }

                    // TODO (canndrew): should eventually be able to remove this conversion
                    let timeout_remaining = ::std::time::Duration::from_millis(timeout_remaining.num_milliseconds() as u64);

                    try!(receiver.set_read_timeout(Some(timeout_remaining)));
                    let mut recv_data = [0u8; 256];
                    let (read_size, recv_addr) = try!(receiver.recv_from(&mut recv_data[..]));
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
            => Ok((udp_socket, Some(our_addr), helper_nodes.iter()
                                                           .cloned()
                                                           .skip(responder_index + 1)
                                                           .collect::<Vec<SocketAddr>>())),
    }
}

pub fn start_hole_punch_server() -> io::Result<(::std::sync::mpsc::Sender<()>, ::std::thread::JoinHandle<io::Result<()>>, SocketAddr)> {
    let (tx, rx) = ::std::sync::mpsc::channel::<()>();
    let udp_socket = try!(UdpSocket::bind("0.0.0.0:0"));
    let local_addr = try!(udp_socket.local_addr());
    /*
     * TODO (canndrew):
     * Currently we set a read timeout so that the hole punch server thread continually wakes
     * and checks to see if it's time to exit. This is a really crappy way of implementing
     * this but currently rust doesn't have a good cross-platform select/epoll interface.
     */
    try!(udp_socket.set_read_timeout(Some(::std::time::Duration::from_millis(500))));
    let hole_punch_listener = try!(::std::thread::Builder::new().name(String::from("udp hole punch server"))
                                                                .spawn(move || {
        loop {
            match rx.try_recv() {
                Err(::std::sync::mpsc::TryRecvError::Empty)        => (),
                Err(::std::sync::mpsc::TryRecvError::Disconnected) => panic!(),
                Ok(())  => return Ok(()),
            }
            let mut data_recv = [0u8; 256];
            let (read_size, addr) = try!(udp_socket.recv_from(&mut data_recv[..]));
            match ::cbor::Decoder::from_reader(&data_recv[..read_size])
                                 .decode::<GetExternalAddr>().next() {
                Some(Ok(gea)) => {
                    if gea.magic != GET_EXTERNAL_ADDR_MAGIC {
                        continue;
                    }
                    let data_send = {
                        let sea = SetExternalAddr {
                            request_id: gea.request_id,
                            addr: WrapSocketAddr(addr),
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
    Ok((tx, hole_punch_listener, local_addr))
}

pub fn blocking_udp_punch_hole(udp_socket: UdpSocket,
                               secret: Option<[u8; 4]>,
                               // TODO (canndrew): ToSocketAddrs would
                               // prolly make more sense
                               peer_addrs: ::std::collections::BTreeSet<SocketAddr>,
                               timeout: Option<::std::time::Duration>)
            -> (UdpSocket, io::Result<SocketAddr>) {
    let send_data = {
        let hole_punch = HolePunch {
            secret: secret,
            ack: false,
        };
        let mut enc = ::cbor::Encoder::from_memory();
        enc.encode(::std::iter::once(&hole_punch)).unwrap();
        enc.into_bytes()
    };

    let peer_addrs = peer_addrs.iter().cloned().collect::<Vec<SocketAddr>>();

    let addr_res: io::Result<SocketAddr> = ::crossbeam::scope(|scope| {
        let sender          = try!(udp_socket.try_clone());
        let receiver        = try!(udp_socket.try_clone());
        let periodic_sender = PeriodicSender::start(sender,
                                                    &peer_addrs[..],
                                                    scope,
                                                    &send_data[..],
                                                    1000);

        let addr_res = (|| {
            let mut recv_data = [0u8; 16];
            try!(receiver.set_read_timeout(timeout));
            loop {
                let (read_size, addr) = try!(receiver.recv_from(&mut recv_data[..]));
                match ::cbor::Decoder::from_reader(&recv_data[..read_size])
                                      .decode::<HolePunch>().next() {
                    Some(Ok(ref hp)) if hp.ack && hp.secret == secret
                        => return Ok(addr),
                    x   => info!("udp_hole_punch received invalid ack: {:?}", x),
                };
            }
        })();

        addr_res
    });

    (udp_socket, addr_res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
    use std::str::FromStr;

    #[test]
    fn test_get_mapped_socket_from_self() {
        let localhost = Ipv4Addr::new(127, 0, 0, 1);
        let (sender, join_handle, local_addr) = start_hole_punch_server().unwrap();
        let (socket, our_addr, remaining) = blocking_get_mapped_udp_socket(12345, vec![SocketAddr::V4(SocketAddrV4::new(localhost, local_addr.port()))]).unwrap();
        sender.send(()).unwrap();
        let received_addr = our_addr.unwrap();
        let socket_addr = socket.local_addr().unwrap();
        assert_eq!(SocketAddr::V4(SocketAddrV4::new(localhost, socket_addr.port())), received_addr);
        assert!(remaining.is_empty());
    }

}

