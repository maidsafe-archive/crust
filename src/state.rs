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

use std::collections::HashMap;
use std::io;
use std::net;
use std::sync::{Arc, mpsc};
use std::sync::mpsc::{Sender, Receiver};
use std::thread;
use std::str::FromStr;

use transport;
use endpoint::Endpoint;
use std::thread::JoinHandle;
use std::net::{UdpSocket, TcpListener};
use ip::{SocketAddrExt, IpAddr};

use event::Event;
use connection::Connection;
use hole_punching::HolePunchServer;
use socket_addr::SocketAddr;


// Closure is a wapper around boxed closures that tries to work around the fact
// that it is not possible to call Box<FnOnce> in the current stable rust.
// The idea is to wrap the FnOnce in something that implements FnMut using some
// dirty tricks, because Box<FnMut> is fine to call.
//
// This workaround can be removed once FnBox becomes stable or Box<FnOnce>
// becomes usable.
pub struct Closure(Box<FnMut(&mut State) + Send>);

impl Closure {
    pub fn new<F: FnOnce(&mut State) + Send + 'static>(f: F) -> Closure {
        let mut f = Some(f);
        Closure(Box::new(move |state: &mut State| {
            if let Some(f) = f.take() {
                f(state)
            }
        }))
    }

    pub fn invoke(mut self, state: &mut State) {
        (self.0)(state)
    }
}

pub struct State {
}

impl State {
    fn new_thread<F, T>(name: &str, f: F) -> io::Result<JoinHandle<T>>
        where F: FnOnce() -> T,
              F: Send + 'static,
              T: Send + 'static
    {
        thread::Builder::new()
            .name("State::".to_owned() + name)
            .spawn(f)
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use std::thread;
    use std::net::{TcpListener, SocketAddrV6};
    use std::net;
    use ip::{SocketAddrExt, IpAddr};
    use std::sync::mpsc::channel;
    use transport::Handshake;
    use endpoint::{Protocol, Endpoint};
    use event::Event;
    use util;
    use socket_addr::SocketAddr;
    use hole_punching::HolePunchServer;
    use std::sync::Arc;

    fn testable_endpoint(listener: &TcpListener) -> Endpoint {
        let addr = unwrap_result!(listener.local_addr());

        let ip = util::loopback_if_unspecified(SocketAddrExt::ip(&addr));
        let addr = match (ip, addr) {
            (IpAddr::V4(ip), _) => net::SocketAddr::V4(net::SocketAddrV4::new(ip, addr.port())),
            (IpAddr::V6(ip), net::SocketAddr::V6(addr)) => {
                net::SocketAddr::V6(SocketAddrV6::new(ip,
                                                      addr.port(),
                                                      addr.flowinfo(),
                                                      addr.scope_id()))
            }
            _ => panic!("Unreachable"),
        };
        Endpoint::from_socket_addr(Protocol::Tcp, SocketAddr(addr))
    }

    fn test_bootstrap_off_list(n: u16) {
        let listeners = (0..n)
                            .map(|_| unwrap_result!(TcpListener::bind("0.0.0.0:0")))
                            .collect::<Vec<_>>();

        let eps = listeners.iter()
                           .map(|a| testable_endpoint(&a))
                           .collect();

        let (category_tx, category_rx) = channel();
        let (event_tx, event_receiver) = channel();
        let crust_event_category =
            ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent;
        let event_sender =
            ::maidsafe_utilities::event_sender::MaidSafeObserver::new(event_tx,
                                                                      crust_event_category,
                                                                      category_tx);

        let mut s = State::new(event_sender).unwrap();

        let cmd_sender = s.cmd_sender.clone();
        let hole_punch_server =
            Arc::new(unwrap_result!(HolePunchServer::start(cmd_sender.clone())));

        cmd_sender.send(Closure::new(move |s: &mut State| {
                      s.bootstrap_off_list(0, eps, hole_punch_server);
                  }))
                  .unwrap();

        let accept_thread = thread::spawn(move || {
            for a in listeners {
                let _ = State::accept(Handshake::default(), &a).unwrap();
            }
        });

        let t = thread::spawn(move || {
            s.run();
        });

        let mut accept_count = 0;

        for it in category_rx.iter() {
            match it {
                ::maidsafe_utilities::event_sender::MaidSafeEventCategory::CrustEvent => {
                    if let Ok(event) = event_receiver.try_recv() {
                        match event {
                            Event::OnConnect(_, _) => {
                                accept_count += 1;
                                if accept_count == n {
                                    cmd_sender.send(Closure::new(move |s: &mut State| {
                                                  s.stop();
                                              }))
                                              .unwrap();
                                    break;
                                }
                            }
                            Event::LostConnection(_) => {}
                            Event::BootstrapFinished => {}
                            _ => {
                                panic!("Unexpected event {:?}", event);
                            }
                        }
                    }
                }
                _ => unreachable!("This category should not have been fired - {:?}", it),
            }
        }

        t.join().unwrap();
        accept_thread.join().unwrap();
    }

    #[test]
    fn bootstrap_off_list() {
        test_bootstrap_off_list(1);
        test_bootstrap_off_list(2);
        test_bootstrap_off_list(4);
        test_bootstrap_off_list(8);
    }
}
