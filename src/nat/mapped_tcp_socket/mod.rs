// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use self::get_ext_addr::GetExtAddr;
use common::{Core, CoreMessage, CoreTimer, State, Uid};
use igd::PortMappingProtocol;
use maidsafe_utilities::thread;
use mio::{Poll, Token};
use mio_extras::timer::Timeout;
use nat::{util, MappingContext, NatError};
use net2::TcpBuilder;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::Rc;
use std::time::Duration;

mod get_ext_addr;

const TIMEOUT_SEC: u64 = 3;

/// A state which represents the in-progress mapping of a tcp socket.
pub struct MappedTcpSocket<F, UID> {
    token: Token,
    socket: Option<TcpBuilder>,
    igd_children: usize,
    stun_children: HashSet<Token>,
    mapped_addrs: Vec<SocketAddr>,
    timeout: Timeout,
    finish: Option<F>,
    phantom: PhantomData<UID>,
}

impl<F, UID> MappedTcpSocket<F, UID>
where
    F: FnOnce(&mut Core, &Poll, TcpBuilder, Vec<SocketAddr>) + Any,
    UID: Uid,
{
    /// Start mapping a tcp socket
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        port: u16,
        mc: &MappingContext,
        finish: F,
    ) -> Result<(), NatError> {
        let token = core.get_new_token();

        // TODO(Spandan) Ipv6 is not supported in Listener so dealing only with ipv4 right now
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);

        let socket = util::new_reusably_bound_tcp_socket(&addr)?;
        let addr = socket.local_addr()?;

        // Ask IGD
        let mut igd_children = 0;
        for &(ref ip, ref gateway) in mc.ifv4s() {
            let gateway = match *gateway {
                Some(ref gateway) => gateway.clone(),
                None => continue,
            };
            let tx = core.sender().clone();
            let addr_igd = SocketAddrV4::new(*ip, addr.port());
            let _ = thread::named("IGD-Address-Mapping", move || {
                let res =
                    gateway.get_any_address(PortMappingProtocol::TCP, addr_igd, 0, "MaidSafeNat");
                let ext_addr = match res {
                    Ok(ext_addr) => ext_addr,
                    Err(_) => return,
                };
                let _ = tx.send(CoreMessage::new(move |core, poll| {
                    let state = match core.get_state(token) {
                        Some(state) => state,
                        None => return,
                    };

                    let mut state = state.borrow_mut();
                    let mapping_tcp_sock =
                        match state.as_any().downcast_mut::<MappedTcpSocket<F, UID>>() {
                            Some(mapping_sock) => mapping_sock,
                            None => return,
                        };
                    mapping_tcp_sock.handle_igd_resp(core, poll, SocketAddr::V4(ext_addr));
                }));
            });
            igd_children += 1;
        }

        let mapped_addrs = mc
            .ifv4s()
            .iter()
            .map(|&(ip, _)| SocketAddr::new(IpAddr::V4(ip), addr.port()))
            .collect();

        let state = Rc::new(RefCell::new(Self {
            token,
            socket: Some(socket),
            igd_children,
            stun_children: HashSet::with_capacity(mc.peer_stuns().len()),
            mapped_addrs,
            timeout: core.set_timeout(Duration::from_secs(TIMEOUT_SEC), CoreTimer::new(token, 0)),
            finish: Some(finish),
            phantom: PhantomData,
        }));

        // Ask Stuns
        for stun in mc.peer_stuns() {
            let self_weak = Rc::downgrade(&state);
            let handler = move |core: &mut Core, poll: &Poll, child_token, res| {
                if let Some(self_rc) = self_weak.upgrade() {
                    self_rc
                        .borrow_mut()
                        .handle_stun_resp(core, poll, child_token, res)
                }
            };

            if let Ok(child) = GetExtAddr::<UID>::start(core, poll, addr, stun, Box::new(handler)) {
                let _ = state.borrow_mut().stun_children.insert(child);
            }
        }

        if state.borrow().stun_children.is_empty() && state.borrow().igd_children == 0 {
            state.borrow_mut().terminate(core, poll);
            return Ok(());
        }

        let _ = core.insert_state(token, state);

        Ok(())
    }

    fn handle_stun_resp(
        &mut self,
        core: &mut Core,
        poll: &Poll,
        child: Token,
        res: Result<SocketAddr, ()>,
    ) {
        let _ = self.stun_children.remove(&child);
        if let Ok(our_ext_addr) = res {
            self.mapped_addrs.push(our_ext_addr);
        }
        if self.stun_children.is_empty() && self.igd_children == 0 {
            self.terminate(core, poll);
        }
    }

    fn handle_igd_resp(&mut self, core: &mut Core, poll: &Poll, our_ext_addr: SocketAddr) {
        self.igd_children -= 1;
        self.mapped_addrs.push(our_ext_addr);
        if self.stun_children.is_empty() && self.igd_children == 0 {
            self.terminate(core, poll);
        }
    }

    fn terminate_children(&mut self, core: &mut Core, poll: &Poll) {
        for token in self.stun_children.drain() {
            let child = match core.get_state(token) {
                Some(state) => state,
                None => continue,
            };

            child.borrow_mut().terminate(core, poll);
        }
    }
}

impl<F, UID> State for MappedTcpSocket<F, UID>
where
    F: FnOnce(&mut Core, &Poll, TcpBuilder, Vec<SocketAddr>) + Any,
    UID: Uid,
{
    fn timeout(&mut self, core: &mut Core, poll: &Poll, _: u8) {
        self.terminate(core, poll)
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        self.terminate_children(core, poll);
        let _ = core.remove_state(self.token);
        let _ = core.cancel_timeout(&self.timeout);

        let socket = unwrap!(self.socket.take());
        let mapped_addrs = self.mapped_addrs.drain(..).collect();
        (unwrap!(self.finish.take()))(core, poll, socket, mapped_addrs);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
