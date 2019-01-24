// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::{Message, NameHash, State};
use crate::main::{ConnectionId, CrustData, EventLoopCore};
use crate::PeerId;
use mio::{Poll, PollOpt, Ready, Token};
use safe_crypto::SharedSecretKey;
use socket_collection::{EncryptContext, Priority, TcpSock};
use std::any::Any;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashSet;
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;

/// When connection messages are exchanged a callback is called with these parameters.
/// A new mio `Token` is assigned to the given socket.
pub type Finish = Box<FnMut(&mut EventLoopCore, &Poll, Token, Option<TcpSock>)>;

/// Exchanges connect messages.
pub struct ExchangeMsg {
    token: Token,
    expected_id: PeerId,
    expected_nh: NameHash,
    socket: TcpSock,
    msg: Option<(Message, Priority)>,
    shared_key: SharedSecretKey,
    finish: Finish,
}

impl ExchangeMsg {
    pub fn start(
        core: &mut EventLoopCore,
        poll: &Poll,
        socket: TcpSock,
        our_id: PeerId,
        expected_id: PeerId,
        name_hash: NameHash,
        shared_key: SharedSecretKey,
        our_global_direct_listeners: HashSet<SocketAddr>,
        finish: Finish,
    ) -> crate::Res<Token> {
        let token = core.get_new_token();

        poll.register(
            &socket,
            token,
            Ready::writable() | Ready::readable(),
            PollOpt::edge(),
        )?;

        let connections = &mut core.user_data_mut().connections;
        connections
            .entry(expected_id)
            .or_insert(ConnectionId {
                active_connection: None,
                currently_handshaking: 0,
            })
            .currently_handshaking += 1;
        trace!(
            "Connection Map inserted: {:?} -> {:?}",
            expected_id,
            connections.get(&expected_id)
        );

        let state = Self {
            token,
            expected_id,
            expected_nh: name_hash,
            socket,
            msg: Some((
                Message::ConnectRequest(our_id, name_hash, our_global_direct_listeners),
                0,
            )),
            shared_key,
            finish,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(token)
    }

    fn write(&mut self, core: &mut EventLoopCore, poll: &Poll, msg: Option<(Message, Priority)>) {
        if self.socket.write(msg).is_err() {
            self.handle_error(core, poll);
        }
    }

    fn receive_response(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        match self.socket.read::<Message>() {
            Ok(Some(Message::ConnectResponse(their_uid, name_hash))) => {
                if their_uid != self.expected_id || name_hash != self.expected_nh {
                    return self.handle_error(core, poll);
                }
                let _ = core.remove_state(self.token);
                let token = self.token;

                let mut socket = mem::replace(&mut self.socket, Default::default());
                match socket.set_encrypt_ctx(EncryptContext::authenticated(self.shared_key.clone()))
                {
                    Ok(_) => (*self.finish)(core, poll, token, Some(socket)),
                    Err(e) => {
                        debug!("Failed to set socket encrypt context: {}", e);
                        self.handle_error(core, poll);
                    }
                }
            }
            Ok(None) => (),
            Ok(Some(_)) | Err(_) => self.handle_error(core, poll),
        }
    }

    fn handle_error(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        self.terminate(core, poll);
        let token = self.token;
        (*self.finish)(core, poll, token, None);
    }
}

impl State<CrustData> for ExchangeMsg {
    fn ready(&mut self, core: &mut EventLoopCore, poll: &Poll, kind: Ready) {
        if kind.is_writable() {
            let req = self.msg.take();
            self.write(core, poll, req);
        }
        if kind.is_readable() {
            self.receive_response(core, poll)
        }
    }

    fn terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.socket);

        let connections = &mut core.user_data_mut().connections;
        if let Entry::Occupied(mut oe) = connections.entry(self.expected_id) {
            oe.get_mut().currently_handshaking -= 1;
            if oe.get().currently_handshaking == 0 && oe.get().active_connection.is_none() {
                let _ = oe.remove();
            }
        }
        trace!(
            "Connection Map removed: {:?} -> {:?}",
            self.expected_id,
            connections.get(&self.expected_id)
        );
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
