extern crate crust;
extern crate mio;
extern crate env_logger;

use crust::core::Core;
use crust::nat::mapping_server::TcpMappingServer;
use crust::nat::mapping_context::MappingContext;
use mio::EventLoop;

fn main() {
    env_logger::init().unwrap();

    let mapping_context = MappingContext::new();
    let mut core = Core::new();
    let mut event_loop = EventLoop::new().unwrap();
    TcpMappingServer::new(&mut core, &mut event_loop, &mapping_context, |_core, _event_loop, addrs| {
        println!("Server addresses: {:?}", addrs);
    }).unwrap();
    event_loop.run(&mut core).unwrap();
}

