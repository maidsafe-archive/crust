// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use common::{BootstrapDenyReason, ExternalReachability, Message, NameHash, PeerInfo, State, Uid};
use main::bootstrap::Cache as BootstrapCache;
use main::EventLoopCore;
use mio::{Poll, PollOpt, Ready, Token};
use safe_crypto::{PublicEncryptKey, SecretEncryptKey, SharedSecretKey};
use socket_collection::{DecryptContext, EncryptContext, Priority, TcpSock};
use std::any::Any;
use std::cell::RefCell;
use std::mem;
use std::rc::Rc;

pub type Finish<UID> = Box<
    FnMut(
        &mut EventLoopCore,
        &Poll,
        Token,
        Result<(TcpSock, PeerInfo, UID), (PeerInfo, Option<BootstrapDenyReason>)>,
    ),
>;

/// Sends bootstrap request to a one specific address and waits for response.
pub struct TryPeer<UID: Uid> {
    token: Token,
    peer: PeerInfo,
    socket: TcpSock,
    request: Option<(Message<UID>, Priority)>,
    finish: Finish<UID>,
    shared_key: SharedSecretKey,
}

impl<UID: Uid> TryPeer<UID> {
    pub fn start(
        core: &mut EventLoopCore,
        poll: &Poll,
        peer: PeerInfo,
        our_uid: UID,
        name_hash: NameHash,
        ext_reachability: ExternalReachability,
        our_pk: PublicEncryptKey,
        our_sk: &SecretEncryptKey,
        finish: Finish<UID>,
    ) -> ::Res<Token> {
        let mut socket = TcpSock::connect(&peer.addr)?;
        socket.set_encrypt_ctx(EncryptContext::anonymous_encrypt(peer.pub_key))?;
        let shared_key = our_sk.shared_secret(&peer.pub_key);
        socket.set_decrypt_ctx(DecryptContext::authenticated(shared_key.clone()))?;
        let token = core.get_new_token();

        poll.register(
            &socket,
            token,
            Ready::writable() | Ready::readable(),
            PollOpt::edge(),
        )?;

        let state = TryPeer {
            token,
            peer,
            socket,
            request: Some((
                Message::BootstrapRequest(our_uid, name_hash, ext_reachability, our_pk),
                0,
            )),
            finish,
            shared_key,
        };

        let _ = core.insert_state(token, Rc::new(RefCell::new(state)));

        Ok(token)
    }

    fn write(
        &mut self,
        core: &mut EventLoopCore,
        poll: &Poll,
        msg: Option<(Message<UID>, Priority)>,
    ) {
        if self.socket.write(msg).is_err() {
            self.handle_error(core, poll, None);
        }
    }

    fn read(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        match self.socket.read::<Message<UID>>() {
            Ok(Some(Message::BootstrapGranted(peer_uid))) => {
                let _ = core.remove_state(self.token);
                let token = self.token;

                let mut socket = mem::replace(&mut self.socket, Default::default());
                match socket.set_encrypt_ctx(EncryptContext::authenticated(self.shared_key.clone()))
                {
                    Ok(_) => {
                        let data = (socket, self.peer, peer_uid);
                        (*self.finish)(core, poll, token, Ok(data));
                    }
                    Err(e) => {
                        warn!("Failed to set socket encrypt context: {}", e);
                        self.handle_error(core, poll, None);
                    }
                }
            }
            Ok(Some(Message::BootstrapDenied(reason))) => {
                self.handle_error(core, poll, Some(reason))
            }
            Ok(None) => (),
            Ok(Some(_)) | Err(_) => self.handle_error(core, poll, None),
        }
    }

    fn handle_error(
        &mut self,
        core: &mut EventLoopCore,
        poll: &Poll,
        reason: Option<BootstrapDenyReason>,
    ) {
        self.terminate(core, poll);
        (*self.finish)(core, poll, self.token, Err((self.peer, reason)));
    }
}

impl<UID: Uid> State<BootstrapCache> for TryPeer<UID> {
    fn ready(&mut self, core: &mut EventLoopCore, poll: &Poll, kind: Ready) {
        if kind.is_writable() || kind.is_readable() {
            if kind.is_writable() {
                let req = self.request.take();
                self.write(core, poll, req);
            }
            if kind.is_readable() {
                self.read(core, poll)
            }
            return;
        }

        debug!(
            "Considering the following event to indicate dirupted connection: {:?}",
            kind
        );
        self.handle_error(core, poll, None);
    }

    fn terminate(&mut self, core: &mut EventLoopCore, poll: &Poll) {
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.socket);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
