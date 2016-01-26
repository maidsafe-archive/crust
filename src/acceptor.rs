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
use std::io;
use std::str::FromStr;

use get_if_addrs::get_if_addrs;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use socket_addr::SocketAddr;
use transport;
use transport::Handshake;
use hole_punching::HolePunchServer;
use connection_map::ConnectionMap;
use endpoint::Endpoint;
use event::Event;
use util;

pub struct Acceptor {
    _joiner: RaiiThreadJoiner,
    running: Arc<AtomicBool>,
    addr: net::SocketAddr,
    mapped_addrs: Vec<SocketAddr>,
}

impl Acceptor {
    pub fn new(listener: TcpListener,
               hole_punch_server: Arc<HolePunchServer>,
               connection_map: Arc<ConnectionMap>)
               -> io::Result<Acceptor> {
        let running = Arc::new(AtomicBool::new(true));
        let running_cloned = running.clone();
        let addr = try!(listener.local_addr());
        let mapped_addrs = try!(get_if_addrs())
                                .into_iter()
                                .filter(|i| !i.is_loopback())
                                .map(|i| SocketAddr::new(i.ip(), addr.port()))
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
                let accept_res = transport::accept(&listener).and_then(|t| {
                    transport::exchange_handshakes(handshake, t)
                });
                if !running_cloned.load(Ordering::SeqCst) {
                    break;
                }
                // TODO (canndrew): What to do with this error?
                let _ = match accept_res {
                    Ok((handshake, transport)) => {
                        let c = transport.connection_id.clone();
                        let protocol = *c.peer_endpoint()
                                         .protocol();
                        let remote_addr = SocketAddr(*handshake.remote_addr);
                        let our_external_endpoint = Endpoint::from_socket_addr(protocol, remote_addr);
                        connection_map.register_connection(handshake, transport, Event::OnBootstrapAccept(our_external_endpoint, c))
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

    #[cfg(test)]
    pub fn with_utp(listener: ::utp::UtpListener,
                    hole_punch_server: Arc<HolePunchServer>,
                    connection_map: Arc<ConnectionMap>)
        -> io::Result<Acceptor> {
        let running = Arc::new(AtomicBool::new(true));
        let running_cloned = running.clone();
        let addr = try!(listener.local_addr());
        let mapped_addrs = try!(get_if_addrs())
                                .into_iter()
                                .filter(|i| !i.is_loopback())
                                .map(|i| SocketAddr::new(i.ip(), addr.port()))
                                .collect();
        let joiner = RaiiThreadJoiner::new(thread!("acceptor-utp", move || {
            loop {
                let mapper_external_addr = hole_punch_server.external_address();
                let mapper_internal_port = hole_punch_server.listening_addr().port();
                let handshake = Handshake {
                    mapper_port: Some(mapper_internal_port),
                    external_addr: mapper_external_addr,
                    remote_addr: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
                };
                let accept_res = transport::accept_utp(&listener).and_then(|t| {
                    transport::exchange_handshakes(handshake, t)
                });
                if !running_cloned.load(Ordering::SeqCst) {
                    break;
                }
                // TODO (canndrew): What to do with this error?
                let _ = match accept_res {
                    Ok((handshake, transport)) => {
                        let c = transport.connection_id.clone();
                        let protocol = *c.peer_endpoint()
                                         .protocol();
                        let remote_addr = SocketAddr(*handshake.remote_addr);
                        let our_external_endpoint = Endpoint::from_socket_addr(protocol, remote_addr);
                        connection_map.register_connection(handshake, transport, Event::OnBootstrapAccept(our_external_endpoint, c))
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
    #[cfg(not(test))]
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = TcpStream::connect(util::unspecified_to_loopback(&self.addr));
    }

    #[cfg(test)]
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = TcpStream::connect(util::unspecified_to_loopback(&self.addr));
        let _ = ::utp::UtpSocket::connect(util::unspecified_to_loopback(&self.addr));
    }
}
