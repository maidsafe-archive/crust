use std::net::{SocketAddr, SocketAddrV4, UdpSocket, SocketAddrV6, Ipv4Addr, Ipv6Addr};
use std::io;

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
        match self.0 {
            SocketAddr::V4(ref v4)  => {
                try!(s.emit_bool(false));
                let ip = v4.ip().octets();
                let port = v4.port();
                try!(s.emit_u8(ip[0]));
                try!(s.emit_u8(ip[1]));
                try!(s.emit_u8(ip[2]));
                try!(s.emit_u8(ip[3]));
                try!(s.emit_u16(port));
            }
            SocketAddr::V6(ref v6) => {
                try!(s.emit_bool(true));
                let ip = v6.ip().segments();
                let port = v6.port();
                let flowinfo = v6.flowinfo();
                let scope_id = v6.scope_id();
                try!(s.emit_u16(ip[0]));
                try!(s.emit_u16(ip[1]));
                try!(s.emit_u16(ip[2]));
                try!(s.emit_u16(ip[3]));
                try!(s.emit_u16(ip[4]));
                try!(s.emit_u16(ip[5]));
                try!(s.emit_u16(ip[6]));
                try!(s.emit_u16(ip[7]));
                try!(s.emit_u16(port));
                try!(s.emit_u32(flowinfo));
                try!(s.emit_u32(scope_id));
            }
        }
        Ok(())
    }
}

impl ::rustc_serialize::Decodable for WrapSocketAddr {
    fn decode<D: ::rustc_serialize::Decoder>(d: &mut D) -> Result<WrapSocketAddr, D::Error> {
        let tag = try!(d.read_bool());
        match tag {
            false   => {
                let a0 = try!(d.read_u8());
                let a1 = try!(d.read_u8());
                let a2 = try!(d.read_u8());
                let a3 = try!(d.read_u8());
                let port = try!(d.read_u16());
                Ok(WrapSocketAddr(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a0, a1, a2, a3), port))))
            }
            true    => {
                let a0 = try!(d.read_u16());
                let a1 = try!(d.read_u16());
                let a2 = try!(d.read_u16());
                let a3 = try!(d.read_u16());
                let a4 = try!(d.read_u16());
                let a5 = try!(d.read_u16());
                let a6 = try!(d.read_u16());
                let a7 = try!(d.read_u16());
                let port = try!(d.read_u16());
                let flowinfo = try!(d.read_u32());
                let scope_id = try!(d.read_u32());
                Ok(WrapSocketAddr(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(a0, a1, a2, a3, a4, a5, a6, a7), port, flowinfo, scope_id))))
            }
        }
    }
}

pub fn blocking_get_mapped_udp_socket(request_id: u32, helper_nodes: Vec<SocketAddr>)
        -> io::Result<(UdpSocket, Option<SocketAddr>, Vec<SocketAddr>)>
{
    let timeout = ::time::Duration::seconds(2);

    let udp_socket = try!(UdpSocket::bind("0.0.0.0:0"));
    let sender = try!(udp_socket.try_clone());
    let receiver = try!(udp_socket.try_clone());

    let send_data = {
        let gea = GetExternalAddr::new(request_id);
        let mut enc = ::cbor::Encoder::from_memory();
        enc.encode(::std::iter::once(&gea)).unwrap();
        enc.into_bytes()
    };

    let res = try!(::crossbeam::scope(|scope| -> io::Result<Option<(SocketAddr, SocketAddr)>> {
        let periodic_sender = PeriodicSender::start(sender, &helper_nodes[..], scope, &send_data[..], 1000);
        let start_time = ::time::now();
        let res = try!((|| -> io::Result<Option<(SocketAddr, SocketAddr)>> {
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
                let mut recv_data = [0u8; 16];
                let (read_size, recv_addr) = try!(receiver.recv_from(&mut recv_data[..]));
                match helper_nodes.iter().position(|&a| a == recv_addr) {
                    None    => continue,
                    Some(i) => match ::cbor::Decoder::from_reader(&recv_data[..read_size])
                                                     .decode::<SetExternalAddr>().next() {
                        Some(Ok(sea)) => {
                            if sea.request_id != request_id {
                                continue;
                            }
                            return Ok(Some((sea.addr.0, recv_addr)))
                        }
                        _   => continue,
                    }
                }
            }
        })());
        //try!(periodic_sender.stop());
        Ok(res)
    }));
    match res {
        None => Ok((udp_socket, None, helper_nodes)),
        Some((our_addr, responder_addr))
            => Ok((udp_socket, Some(our_addr), helper_nodes.iter()
                                                           .cloned()
                                                           .filter(|&a| a != responder_addr)
                                                           .collect::<Vec<SocketAddr>>())),
    }
}

