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

mod accept_connection;

use mio::{EventLoop, EventSet, PollOpt, Token};
use mio::tcp::TcpListener;
use sodiumoxide::crypto::box_::PublicKey;
use std::any::Any;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use self::accept_connection::AcceptConnection;
use core::{Core, State};
use event::Event;
use nat::mapped_tcp_socket::MappingTcpSocket;
use nat::mapping_context::MappingContext;
use service::SharedConnectionMap;
use socket::Socket;
use static_contact_info::StaticContactInfo;

pub struct ConnectionListener {
    connection_map: SharedConnectionMap,
    event_tx: ::CrustEventSender,
    listener: TcpListener,
    name_hash: u64,
    our_public_key: PublicKey,
    token: Token,
}

impl ConnectionListener {
    pub fn start(core: &mut Core,
                 event_loop: &mut EventLoop<Core>,
                 port: u16,
                 our_public_key: PublicKey,
                 name_hash: u64,
                 connection_map: SharedConnectionMap,
                 mapping_context: Arc<MappingContext>,
                 static_contact_info: Arc<Mutex<StaticContactInfo>>,
                 event_tx: ::CrustEventSender) {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        let event_tx_clone = event_tx.clone();
        // let mapping_context_clone = mapping_context.clone();
        match MappingTcpSocket::new(core, event_loop, &addr, &mapping_context,
                                    move |core, event_loop, socket, addrs| {
            let context = core.get_new_context();
            let token = core.get_new_token();
            let listener = match socket.listen(1) {
                Ok(listener) => listener,
                Err(error) => {
                    error!("Failed to bind TCP listener: {:?}", error);
                    let _ = event_tx.send(Event::ListenerFailed);
                    return;
                }
            };
            let local_addr = match listener.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    error!("Failed to retrieve local address from the TCP listener: {:?}", error);
                    let _ = event_tx.send(Event::ListenerFailed);
                    return;
                }
            };
            let _ = event_tx.send(Event::ListenerStarted(local_addr.port()));

            let listener = TcpListener::from_listener(listener, &addr).expect("start listener error");
            event_loop.register(&listener,
                                token,
                                EventSet::readable() | EventSet::error() | EventSet::hup(),
                                PollOpt::edge())
                      .expect("register to event loop error");
            let _ = core.insert_context(token, context.clone());
            let _ = core.insert_state(context.clone(), ConnectionListener {
                connection_map: connection_map,
                event_tx: event_tx,
                listener: listener,
                name_hash: name_hash,
                our_public_key: our_public_key,
                token: token,
            });

            static_contact_info.lock()
                               .expect("Failed in locking static_contact_info")
                               .tcp_acceptors
                               .extend(addrs);
        }) {
            Ok(()) => {}
            Err(e) => {
                debug!("Error start tcp_listening_socket: {}", e);
                let _ = event_tx_clone.send(Event::ListenerFailed);
            },
        }
    }

    fn handle_accept(&mut self,
                     core: &mut Core,
                     event_loop: &mut EventLoop<Core>,
                     socket: Socket) {
        AcceptConnection::start(core,
                                event_loop,
                                socket,
                                self.our_public_key.clone(),
                                self.name_hash,
                                self.connection_map.clone(),
                                self.event_tx.clone())
    }
}

impl State for ConnectionListener {
    fn ready(&mut self,
             core: &mut Core,
             event_loop: &mut EventLoop<Core>,
             token: Token,
             event_set: EventSet)
    {
        assert_eq!(token, self.token);
        assert!(event_set.is_readable());

        match self.listener.accept() {
            Ok(Some((socket, _))) => self.handle_accept(core, event_loop, Socket::wrap(socket)),
            Ok(None) => (),
            Err(err) => error!("Failed to accept new socket: {:?}", err),
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
