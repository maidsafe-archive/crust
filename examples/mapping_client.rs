extern crate crust;
extern crate mio;
extern crate env_logger;
extern crate socket_addr;
extern crate rustc_serialize;
#[macro_use]
extern crate log;

use std::net::ToSocketAddrs;
use std::any::Any;
use std::rc::Rc;
use std::cell::RefCell;

use crust::core::Core;
use crust::core::state::State;
use crust::nat::MappingTcpSocket;
use crust::nat::MappingContext;
use crust::nat::punch_hole::PunchHole;
use crust::nat::rendezvous_info::gen_rendezvous_info;
use mio::{EventLoop, EventSet, Token};
use mio::{TryRead, TryWrite};
use mio::tcp::TcpStream;
use socket_addr::SocketAddr;

fn main() {
    env_logger::init().unwrap();

    println!("This example allows you to connect to two hosts over TCP through NATs and \
              firewalls.");

    let mut mapping_context = MappingContext::new().expect("Could not instantiate MC");

    // Now we can register a set of external hole punching servers that may be needed to complete
    // the hole punching.
    loop {
        println!("");
        println!("Enter the socket addresses of a simple hole punching server or hit return for \
                  none.");
        println!("");
        let mut addr_str = String::new();
        match std::io::stdin().read_line(&mut addr_str) {
            Ok(_) => (),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    println!("Exiting.");
                    return;
                }
                println!("IO error reading stdin: {}", e);
                return;
            }
        };
        let addr_str = addr_str.trim();
        if addr_str == "" {
            break;
        }
        let mut addrs = match addr_str.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(e) => {
                println!("Error parsing socket address: {}", e);
                continue;
            }
        };
        let addr = match addrs.next() {
            Some(addr) => SocketAddr(addr),
            None => {
                println!("Invalid value");
                continue;
            }
        };
        println!("Registering address: {:#?}", addr);
        mapping_context.add_peer_listeners_no_check(vec![addr.0]);
    }

    let mut core = Core::new();
    let mut event_loop = EventLoop::new().unwrap();
    MappingTcpSocket::start(&mut core,
                            &mut event_loop,
                            0,
                            &mapping_context,
                            |core, event_loop, socket, addrs| {
        let addrs = addrs.into_iter().map(|elt| elt.addr).collect();
        println!("Created a socket. It's endpoints are: {:#?}", addrs);
        let (our_priv_info, our_pub_info) = gen_rendezvous_info(addrs);

        println!("Your public rendezvous info is:");
        println!("");
        println!("{}", rustc_serialize::json::encode(&our_pub_info).unwrap());
        println!("");

        let their_pub_info;
        loop {
            println!("Paste the peer's pub rendezvous info below and when you are ready to \
                      initiate");
            println!("the connection hit return. The peer must initiate their side of the \
                      connection");
            println!("at the same time.");
            println!("");

            let mut info_str = String::new();
            match std::io::stdin().read_line(&mut info_str) {
                Ok(_) => (),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        println!("Exiting.");
                        return;
                    }
                    println!("IO error reading stdin: {}", e);
                    return;
                }
            };
            match rustc_serialize::json::decode(&info_str) {
                Ok(info) => {
                    their_pub_info = info;
                    break;
                }
                Err(e) => {
                    println!("Error decoding their public rendezvous info: {}", e);
                    println!("Push sure to paste their complete info all in one line.");
                }
            }
        }

        let res = PunchHole::start(core,
                                   event_loop,
                                   socket,
                                   our_priv_info,
                                   their_pub_info,
                                   |core, event_loop, stream_opt| {
            let (mut stream, token) = match stream_opt {
                Some(x) => x,
                None => {
                    println!("Failed to punch hole");
                    return;
                }
            };

            println!("Connected! Sending hello");

            match stream.try_write(b"hello") {
                Ok(_) => (),
                Err(e) => {
                    println!("Error writing to socket: {}", e);
                    return;
                }
            };

            MessageReader::start(core, event_loop, stream, token);

            // let token = core.get_new_token();
            // let context = core.get_new_context();
            // event_loop.register(&stream, token, EventSet::all(), PollOpt::edge());
            // core.insert_context(token, context.clone());
            // let client = Client { stream: stream };
            // core.insert_state(context, Rc::new(RefCell::new(client)));
            //
        });
        match res {
            Ok(()) => (),
            Err(e) => {
                println!("Error starting hole punching: {}", e);
            }
        }
    })
        .unwrap();
    event_loop.run(&mut core).unwrap();
}

struct MessageReader {
    stream: TcpStream,
}

impl MessageReader {
    pub fn start(core: &mut Core,
                 _event_loop: &mut EventLoop<Core>,
                 stream: TcpStream,
                 token: Token) {
        let context = core.get_new_context();
        let _ = core.insert_context(token, context.clone());
        let _ = core.insert_state(context,
                                  Rc::new(RefCell::new(MessageReader { stream: stream })));
    }
}

impl State for MessageReader {
    fn ready(&mut self,
             _core: &mut Core,
             _event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet) {
        debug!("MessageReader ready: {:?} {:?}", token, event_set);
        let mut buf = [0u8; 256];
        match self.stream.try_read(&mut buf[..]) {
            Ok(Some(n)) => {
                match std::str::from_utf8(&buf[..n]) {
                    Ok(s) => {
                        println!("Got message from peer: {:?}", s);
                    }
                    Err(e) => {
                        println!("Got some invalid utf-8 from the peer: {:?} ({})",
                                 &buf[..n],
                                 e);
                    }
                }
            }
            Ok(None) => debug!("Stream wasn't ready"),
            Err(e) => {
                println!("Error receiving message from peer: {}", e);
            }
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
