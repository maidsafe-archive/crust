// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::{CoreTimer, CrustUser, Message, PeerInfo, State};
use crate::main::bootstrap::test_inactive_cached_peers;
use crate::main::{ConnectionId, CrustData, Event, EventLoopCore};
use crate::PeerId;
use mio::{Poll, Ready, Token};
use mio_extras::timer::Timeout;
use socket_collection::{Priority, TcpSock};
use std::any::Any;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

#[cfg(not(test))]
pub const INACTIVITY_TIMEOUT_MS: u64 = 120_000;
#[cfg(not(test))]
const HEARTBEAT_PERIOD_MS: u64 = 20_000;

#[cfg(test)]
pub const INACTIVITY_TIMEOUT_MS: u64 = 900;
#[cfg(test)]
const HEARTBEAT_PERIOD_MS: u64 = 300;

pub struct ActiveConnection {
    token: Token,
    socket: TcpSock,
    our_id: PeerId,
    their_id: PeerId,
    their_role: CrustUser,
    event_tx: crate::CrustEventSender,
    heartbeat: Heartbeat,
    peer_info: PeerInfo,
}

impl ActiveConnection {
    pub fn start(
        core: &mut EventLoopCore,
        poll: &Poll,
        token: Token,
        socket: TcpSock,
        our_id: PeerId,
        their_id: PeerId,
        their_role: CrustUser,
        event: Event,
        event_tx: crate::CrustEventSender,
    ) {
        trace!(
            "Entered state ActiveConnection: {:?} -> {:?}",
            our_id,
            their_id
        );

        let their_addr = if let Ok(addr) = socket.peer_addr() {
            addr
        } else {
            debug!("Failed to get active connection socket address.");
            return;
        };
        let peer_info = PeerInfo::new(their_addr, their_id.pub_enc_key);

        let heartbeat = Heartbeat::new(core, token);
        let state = Rc::new(RefCell::new(ActiveConnection {
            token,
            socket,
            our_id,
            their_id,
            their_role,
            event_tx,
            heartbeat,
            peer_info,
        }));
        let _ = core.insert_state(token, state.clone());

        let connections = &mut core.user_data_mut().connections;
        let conn_id = connections.entry(their_id).or_insert(ConnectionId {
            active_connection: None,
            currently_handshaking: 1,
        });
        conn_id.currently_handshaking -= 1;
        conn_id.active_connection = Some(token);
        trace!(
            "Connection Map inserted: {:?} -> {:?}",
            their_id,
            connections.get(&their_id)
        );

        let mut state_mut = state.borrow_mut();
        let _ = state_mut.event_tx.send(event);
        state_mut.read(core, poll);
    }

    fn read(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        loop {
            match self.socket.read::<Message>() {
                Ok(Some(Message::Data(data))) => {
                    let _ =
                        self.event_tx
                            .send(Event::NewMessage(self.their_id, self.their_role, data));
                    self.reset_receive_heartbeat(core, poll);
                    self.updated_bootstrap_cache(core, poll);
                }
                Ok(Some(Message::Heartbeat)) => {
                    self.reset_receive_heartbeat(core, poll);
                    self.updated_bootstrap_cache(core, poll);
                }
                Ok(Some(message)) => {
                    debug!("{:?} - Unexpected message: {:?}", self.our_id, message);
                    self.reset_receive_heartbeat(core, poll);
                    self.updated_bootstrap_cache(core, poll);
                }
                Ok(None) => return,
                Err(e) => {
                    debug!("{:?} - Failed to read from socket: {:?}", self.our_id, e);
                    return self.terminate(core, poll);
                }
            }
        }
    }

    #[cfg(not(test))]
    /// Helper function that returns a socket address of the connection
    pub fn peer_addr(&self) -> crate::Res<SocketAddr> {
        use crate::main::CrustError;
        self.socket.peer_addr().map_err(CrustError::SocketError)
    }

    #[cfg(test)]
    // TODO(nbaksalyar) find a better way to mock connection IPs
    pub fn peer_addr(&self) -> crate::Res<SocketAddr> {
        use std::str::FromStr;
        Ok(unwrap!(FromStr::from_str("192.168.0.1:0")))
    }

    pub fn peer_kind(&self) -> CrustUser {
        self.their_role
    }

    fn write(&mut self, core: &mut EventLoopCore, poll: &Poll, msg: Option<(Message, Priority)>) {
        if let Err(e) = self.socket.write(msg) {
            debug!("{:?} - Failed to write socket: {:?}", self.our_id, e);
            self.terminate(core, poll);
        } else {
            self.updated_bootstrap_cache(core, poll);
        }
    }

    fn reset_receive_heartbeat(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        if let Err(e) = self.heartbeat.reset_receive(core) {
            debug!("{:?} - Failed to reset heartbeat: {:?}", self.our_id, e);
            self.terminate(core, poll);
        }
    }

    fn reset_send_heartbeat(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        if let Err(e) = self.heartbeat.reset_send(core) {
            debug!("{:?} - Failed to reset heartbeat: {:?}", self.our_id, e);
            self.terminate(core, poll);
        }
    }

    /// If peer we are communicating with is in bootstrap cache, move it to the top of the cache.
    fn updated_bootstrap_cache(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        let expired_peers = core.user_data_mut().bootstrap_cache.touch(&self.peer_info);
        core.user_data_mut().bootstrap_cache.try_commit();
        test_inactive_cached_peers(core, poll, expired_peers);
    }
}

impl State<CrustData> for ActiveConnection {
    fn ready(&mut self, core: &mut EventLoopCore, poll: &Poll, kind: Ready) {
        if kind.is_writable() {
            self.write(core, poll, None);
        }
        if kind.is_readable() {
            self.read(core, poll);
        }
    }

    fn write(&mut self, core: &mut EventLoopCore, poll: &Poll, data: Vec<u8>, priority: Priority) {
        self.write(core, poll, Some((Message::Data(data), priority)));
        self.reset_send_heartbeat(core, poll);
    }

    fn terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        self.heartbeat.terminate(core);
        let _ = poll.deregister(&self.socket);
        let _ = core.remove_state(self.token);

        let connections = &mut core.user_data_mut().connections;
        if let Entry::Occupied(mut oe) = connections.entry(self.their_id) {
            oe.get_mut().active_connection = None;
            if oe.get().currently_handshaking == 0 {
                let _ = oe.remove();
            }
        }
        trace!(
            "Connection Map removed: {:?} -> {:?}",
            self.their_id,
            connections.get(&self.their_id)
        );

        let _ = self.event_tx.send(Event::LostPeer(self.their_id));
    }

    fn timeout(&mut self, core: &mut EventLoopCore, poll: &Poll, timer_id: u8) {
        match self.heartbeat.timeout(core, timer_id) {
            HeartbeatAction::Send => self.write(core, poll, Some((Message::Heartbeat, 0))),
            HeartbeatAction::Terminate => {
                debug!(
                    "Dropping connection to {:?} due to peer inactivity",
                    self.their_id
                );
                self.terminate(core, poll);
            }
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

struct Heartbeat {
    recv_timeout: Timeout,
    recv_timer: CoreTimer,
    send_timeout: Timeout,
    send_timer: CoreTimer,
}

impl Heartbeat {
    fn new(core: &mut EventLoopCore, state_id: Token) -> Self {
        let recv_timer = CoreTimer::new(state_id, 0);
        let recv_timeout =
            core.set_timeout(Duration::from_millis(INACTIVITY_TIMEOUT_MS), recv_timer);

        let send_timer = CoreTimer::new(state_id, 1);
        let send_timeout = core.set_timeout(Duration::from_millis(HEARTBEAT_PERIOD_MS), send_timer);

        Self {
            recv_timeout,
            recv_timer,
            send_timeout,
            send_timer,
        }
    }

    fn timeout(&mut self, core: &mut EventLoopCore, timer_id: u8) -> HeartbeatAction {
        if timer_id == self.recv_timer.timer_id {
            HeartbeatAction::Terminate
        } else {
            self.send_timeout =
                core.set_timeout(Duration::from_millis(HEARTBEAT_PERIOD_MS), self.send_timer);
            HeartbeatAction::Send
        }
    }

    fn reset_receive(&mut self, core: &mut EventLoopCore) -> crate::Res<()> {
        let _ = core.cancel_timeout(&self.recv_timeout);
        self.recv_timeout = core.set_timeout(
            Duration::from_millis(INACTIVITY_TIMEOUT_MS),
            self.recv_timer,
        );
        Ok(())
    }

    fn reset_send(&mut self, core: &mut EventLoopCore) -> crate::Res<()> {
        let _ = core.cancel_timeout(&self.send_timeout);
        self.send_timeout =
            core.set_timeout(Duration::from_millis(HEARTBEAT_PERIOD_MS), self.send_timer);
        Ok(())
    }

    fn terminate(&mut self, core: &mut EventLoopCore) {
        let _ = core.cancel_timeout(&self.recv_timeout);
        let _ = core.cancel_timeout(&self.send_timeout);
    }
}

enum HeartbeatAction {
    Send,
    Terminate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ipv4_addr;
    use crate::main::bootstrap;
    use crate::tests::utils::{
        get_event_sender, peer_info_with_rand_key, rand_peer_id_and_enc_sk, test_core,
    };
    use hamcrest2::prelude::*;
    use mio::{Events, Poll, PollOpt, Ready, Token};
    use std::net::TcpListener;
    use std::thread;

    fn wait_until_connected(sock: &TcpSock) {
        const SOCKET_TOKEN: Token = Token(0);
        let el = unwrap!(Poll::new());
        unwrap!(el.register(sock, SOCKET_TOKEN, Ready::writable(), PollOpt::edge()));
        let mut events = Events::with_capacity(16);
        loop {
            unwrap!(el.poll(&mut events, None));
            for ev in events.iter() {
                match ev.token() {
                    SOCKET_TOKEN => return,
                    _ => panic!("Unexpected event"),
                }
            }
        }
    }

    mod active_connection {
        use super::*;

        mod write {
            use super::*;
            use std::io::Read;

            #[test]
            fn it_moves_peer_to_the_top_of_the_bootstrap_cache() {
                let listener = unwrap!(TcpListener::bind(ipv4_addr(0, 0, 0, 0, 0)));
                let listener_port = unwrap!(listener.local_addr()).port();
                let _listener_thread = thread::spawn(move || {
                    // just to block the listener
                    let mut sock = unwrap!(unwrap!(listener.incoming().next()));
                    let mut buf = [0; 4096];
                    let _ = sock.read(&mut buf);
                });

                let (peer1_id, _) = rand_peer_id_and_enc_sk();
                let peer1_sock = unwrap!(TcpSock::connect(&ipv4_addr(127, 0, 0, 1, listener_port)));
                wait_until_connected(&peer1_sock);
                let peer1_addr = unwrap!(peer1_sock.peer_addr());
                let peer1_info = PeerInfo::new(peer1_addr, peer1_id.pub_enc_key);

                let mut cache = bootstrap::Cache::new(Default::default());
                let _ = cache.put(peer1_info);
                let _ = cache.put(peer_info_with_rand_key(ipv4_addr(1, 2, 3, 4, 4000)));

                let mut core = test_core(cache);
                let poll = unwrap!(Poll::new());
                let (event_tx, _event_rx) = get_event_sender();
                let (our_id, _) = rand_peer_id_and_enc_sk();
                let event = Event::ConnectSuccess(peer1_id);
                let token = Token(1);
                ActiveConnection::start(
                    &mut core,
                    &poll,
                    token,
                    peer1_sock,
                    our_id,
                    peer1_id,
                    CrustUser::Client,
                    event,
                    event_tx,
                );

                let state = unwrap!(core.get_state(token));
                let mut state = state.borrow_mut();
                let active_conn = unwrap!(state.as_any().downcast_mut::<ActiveConnection>());
                active_conn.write(&mut core, &poll, None);

                let cached_addrs: Vec<_> = core
                    .user_data()
                    .bootstrap_cache
                    .snapshot()
                    .iter()
                    .map(|peer| peer.addr)
                    .collect();
                assert_that!(
                    &cached_addrs,
                    contains(vec![peer1_addr, ipv4_addr(1, 2, 3, 4, 4000),])
                        .in_order()
                        .exactly()
                );
            }
        }
    }
}
