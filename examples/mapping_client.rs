extern crate crust;
extern crate mio;
extern crate env_logger;

use std::env;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::str::FromStr;

use crust::core::Core;
use crust::nat::mapped_tcp_socket::MappingTcpSocket;
use crust::nat::mapping_context::MappingContext;
use mio::EventLoop;

fn main() {
    env_logger::init().unwrap();

    let args = env::args().skip(1);
    let mut server_addrs = Vec::new();
    for arg in args {
        let addr = SocketAddr::from_str(&arg).unwrap();
        server_addrs.push(addr);
    }

    println!("Server addrs: {:?}", server_addrs);

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
    let mut mapping_context = MappingContext::new();
    mapping_context.add_tcp_mapping_servers(server_addrs);
    let mut core = Core::new();
    let mut event_loop = EventLoop::new().unwrap();
    MappingTcpSocket::new(&mut core, &mut event_loop, &addr, &mapping_context,
                          |_core, _event_loop, _socket, addrs| {
        println!("Our addrs: {:?}", addrs);
    }).unwrap();
    event_loop.run(&mut core).unwrap();
}


