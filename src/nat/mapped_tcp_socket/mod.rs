// Copyright 2016 MaidSafe.net limited.
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


use common::{Core, CoreMessage, CoreTimerId, State};
use igd::PortMappingProtocol;
use maidsafe_utilities::thread;
use mio::{EventLoop, Timeout, Token};
use nat::{MappingContext, NatError, util};
use net2::TcpBuilder;
use self::get_ext_addr::GetExtAddr;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::Rc;

mod get_ext_addr;

const TIMEOUT_MS: u64 = 3 * 1000;

/// A state which represents the in-progress mapping of a tcp socket.
pub struct MappedTcpSocket<F> {
    token: Token,
    socket: Option<TcpBuilder>,
    igd_children: usize,
    stun_children: HashSet<Token>,
    mapped_addrs: Vec<SocketAddr>,
    timeout: Timeout,
    finish: Option<F>,
}

impl<F> MappedTcpSocket<F>
    where F: FnOnce(&mut Core, &mut EventLoop<Core>, TcpBuilder, Vec<SocketAddr>) + Any
{
    /// Start mapping a tcp socket
    pub fn start(core: &mut Core,
                 el: &mut EventLoop<Core>,
                 port: u16,
                 mc: &MappingContext,
                 finish: F)
                 -> Result<(), NatError> {
        let token = core.get_new_token();

        // TODO(Spandan) Ipv6 is not supported in Listener so dealing only with ipv4 right now
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);

        let socket = try!(util::new_reusably_bound_tcp_socket(&addr));
        let addr = try!(util::tcp_builder_local_addr(&socket));

        // Ask IGD
        let mut igd_children = 0;
        for &(ref ip, ref gateway) in mc.ifv4s() {
            let gateway = match *gateway {
                Some(ref gateway) => gateway.clone(),
                None => continue,
            };
            let tx = el.channel();
            let addr_igd = SocketAddrV4::new(*ip, addr.port());
            let _ = thread::named("IGD-Address-Mapping", move || {
                let res =
                    gateway.get_any_address(PortMappingProtocol::TCP, addr_igd, 0, "MaidSafeNat");
                let ext_addr = match res {
                    Ok(ext_addr) => ext_addr,
                    Err(_) => return,
                };
                let _ = tx.send(CoreMessage::new(move |core, el| {
                    let state = match core.get_state(token) {
                        Some(state) => state,
                        None => return,
                    };

                    let mut state = state.borrow_mut();
                    let mapping_tcp_sock = match state.as_any()
                        .downcast_mut::<MappedTcpSocket<F>>() {
                        Some(mapping_sock) => mapping_sock,
                        None => return,
                    };
                    mapping_tcp_sock.handle_igd_resp(core, el, SocketAddr::V4(ext_addr));
                }));
            });
            igd_children += 1;
        }

        let mapped_addrs = mc.ifv4s()
            .iter()
            .map(|&(ip, _)| SocketAddr::new(IpAddr::V4(ip), addr.port()))
            .collect();

        let state = Rc::new(RefCell::new(MappedTcpSocket {
            token: token,
            socket: Some(socket),
            igd_children: igd_children,
            stun_children: HashSet::with_capacity(mc.peer_stuns().len()),
            mapped_addrs: mapped_addrs,
            timeout: try!(el.timeout_ms(CoreTimerId::new(token, 0), TIMEOUT_MS)),
            finish: Some(finish),
        }));

        // Ask Stuns
        for stun in mc.peer_stuns() {
            let self_weak = Rc::downgrade(&state);
            let handler = move |core: &mut Core, el: &mut EventLoop<Core>, child_token, res| {
                if let Some(self_rc) = self_weak.upgrade() {
                    self_rc.borrow_mut().handle_stun_resp(core, el, child_token, res)
                }
            };

            if let Ok(child) = GetExtAddr::start(core, el, addr, stun, Box::new(handler)) {
                let _ = state.borrow_mut().stun_children.insert(child);
            }
        }

        if state.borrow().stun_children.is_empty() && state.borrow().igd_children == 0 {
            return Ok(state.borrow_mut().terminate(core, el));
        }

        let _ = core.insert_state(token, state);

        Ok(())
    }

    fn handle_stun_resp(&mut self,
                        core: &mut Core,
                        el: &mut EventLoop<Core>,
                        child: Token,
                        res: Result<SocketAddr, ()>) {
        let _ = self.stun_children.remove(&child);
        if let Ok(our_ext_addr) = res {
            self.mapped_addrs.push(our_ext_addr);
        }
        if self.stun_children.is_empty() && self.igd_children == 0 {
            self.terminate(core, el);
        }
    }

    fn handle_igd_resp(&mut self,
                       core: &mut Core,
                       el: &mut EventLoop<Core>,
                       our_ext_addr: SocketAddr) {
        self.igd_children -= 1;
        self.mapped_addrs.push(our_ext_addr);
        if self.stun_children.is_empty() && self.igd_children == 0 {
            self.terminate(core, el);
        }
    }

    fn terminate_children(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        for token in self.stun_children.drain() {
            let child = match core.get_state(token) {
                Some(state) => state,
                None => continue,
            };

            child.borrow_mut().terminate(core, el);
        }
    }
}

impl<F> State for MappedTcpSocket<F>
    where F: FnOnce(&mut Core, &mut EventLoop<Core>, TcpBuilder, Vec<SocketAddr>) + Any
{
    fn timeout(&mut self, core: &mut Core, el: &mut EventLoop<Core>, _: u8) {
        self.terminate(core, el)
    }

    fn terminate(&mut self, core: &mut Core, el: &mut EventLoop<Core>) {
        self.terminate_children(core, el);
        let _ = core.remove_state(self.token);
        let _ = el.clear_timeout(self.timeout);

        let socket = unwrap!(self.socket.take());
        let mapped_addrs = self.mapped_addrs.drain(..).collect();
        (unwrap!(self.finish.take()))(core, el, socket, mapped_addrs);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
