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
//
use std::sync::Arc;
use std::net;
use std::sync::atomic::{Ordering, AtomicBool};
use std::net::{TcpStream, TcpListener};
use std::sync::mpsc::Sender;
use std::io;

use get_if_addrs::{getifaddrs, filter_loopback};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use socket_addr::SocketAddr;
use state::{State, Closure};
use transport::Handshake;
use hole_punching::HolePunchServer;
use std::str::FromStr;

pub struct Acceptor {
    _joiner: RaiiThreadJoiner,
    running: Arc<AtomicBool>,
    addr: net::SocketAddr,
    mapped_addrs: Vec<SocketAddr>,
}

impl Acceptor {
    pub fn new(listener: TcpListener,
               hole_punch_server: Arc<HolePunchServer>,
               cmd_sender: Sender<Closure>)
               -> io::Result<Acceptor> {
        let running = Arc::new(AtomicBool::new(true));
        let running_cloned = running.clone();
        let addr = try!(listener.local_addr());
        let mapped_addrs = filter_loopback(getifaddrs())
                               .into_iter()
                               .map(|iface| SocketAddr::new(iface.addr, addr.port()))
                               .collect();
        let joiner = RaiiThreadJoiner::new(thread!("acceptor", move || {
            loop {
                let mapper_external_addr = hole_punch_server.external_address();
                let mapper_internal_port = hole_punch_server.listening_addr().port();
                let handshake = Handshake {
                    mapper_port: Some(mapper_internal_port),
                    external_addr: mapper_external_addr,
                    remote_addr: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
                };
                let accept_res = State::accept(handshake, &listener);
                if !running_cloned.load(Ordering::SeqCst) {
                    break;
                }
                match accept_res {
                    Ok((handshake, transport)) => {
                        let _ = cmd_sender.send(Closure::new(move |state: &mut State| {
                            let _ = state.handle_accept(handshake, transport);
                        }));
                    }
                    Err(e) => {
                        warn!("Acceptor got an error: {} {:?}", e, e);
                        break;
                    }
                };
            }
        }));

        Ok(Acceptor {
            _joiner: joiner,
            running: running,
            addr: addr,
            mapped_addrs: mapped_addrs,
        })
    }

    pub fn local_address(&self) -> SocketAddr {
        SocketAddr(self.addr)
    }

    pub fn mapped_addresses(&self) -> Vec<SocketAddr> {
        self.mapped_addrs.clone()
    }
}

impl Drop for Acceptor {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}
