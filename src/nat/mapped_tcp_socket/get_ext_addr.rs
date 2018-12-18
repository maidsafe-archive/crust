// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use common::{Core, Message, PeerInfo, State, Uid};
use mio::net::TcpStream;
use mio::{Poll, PollOpt, Ready, Token};
use nat::{util, NatError};
use safe_crypto::{PublicEncryptKey, SecretEncryptKey};
use socket_collection::{DecryptContext, EncryptContext, Priority, TcpSock};
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;

pub type Finish = Box<FnMut(&mut Core, &Poll, Token, Result<SocketAddr, ()>)>;

pub struct GetExtAddr<UID: Uid> {
    token: Token,
    socket: TcpSock,
    request: Option<(Message<UID>, Priority)>,
    finish: Finish,
}

impl<UID: Uid> GetExtAddr<UID> {
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        local_addr: SocketAddr,
        peer_stun: &PeerInfo,
        our_pk: PublicEncryptKey,
        our_sk: &SecretEncryptKey,
        finish: Finish,
    ) -> Result<Token, NatError> {
        let query_socket = util::new_reusably_bound_tcp_socket(&local_addr)?;
        let query_socket = query_socket.to_tcp_stream()?;

        let socket = TcpStream::connect_stream(query_socket, &peer_stun.addr)?;
        let mut socket = TcpSock::wrap(socket);
        socket.set_encrypt_ctx(EncryptContext::anonymous_encrypt(peer_stun.pub_key))?;
        let shared_key = our_sk.shared_secret(&peer_stun.pub_key);
        socket.set_decrypt_ctx(DecryptContext::authenticated(shared_key))?;

        let token = core.get_new_token();
        let state = Self {
            token,
            socket,
            request: Some((Message::EchoAddrReq(our_pk), 0)),
            finish,
        };

        poll.register(
            &state.socket,
            token,
            Ready::writable() | Ready::readable(),
            PollOpt::edge(),
        )?;

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(token)
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, msg: Option<(Message<UID>, Priority)>) {
        if self.socket.write(msg).is_err() {
            self.handle_error(core, poll);
        }
    }

    fn receive_response(&mut self, core: &mut Core, poll: &Poll) {
        match self.socket.read::<Message<UID>>() {
            Ok(Some(Message::EchoAddrResp(ext_addr))) => {
                self.terminate(core, poll);
                let token = self.token;
                (*self.finish)(core, poll, token, Ok(ext_addr))
            }
            Ok(None) => (),
            Ok(Some(_)) | Err(_) => self.handle_error(core, poll),
        }
    }

    fn handle_error(&mut self, core: &mut Core, poll: &Poll) {
        self.terminate(core, poll);
        let token = self.token;
        (*self.finish)(core, poll, token, Err(()));
    }
}

impl<UID: Uid> State for GetExtAddr<UID> {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_writable() {
            let req = self.request.take();
            self.write(core, poll, req);
        }
        if kind.is_readable() {
            self.receive_response(core, poll)
        }
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.socket);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
