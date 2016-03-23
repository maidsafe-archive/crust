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
use std::net::{IpAddr, UdpSocket};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use maidsafe_utilities::serialisation::{deserialise, serialise};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use nat_traversal::{MappedUdpSocket, MappingContext, PunchedUdpSocket, gen_rendezvous_info};
use sodiumoxide::crypto::box_::PublicKey;

use connection::{Connection, utp_rendezvous_connect, UtpRendezvousConnectMode};
use static_contact_info::StaticContactInfo;
use socket_addr::SocketAddr;
use listener_message::{ListenerRequest, ListenerResponse};
use peer_id::PeerId;
use bootstrap_handler::BootstrapHandler;

const UDP_READ_TIMEOUT_SECS: u64 = 2;


pub struct RaiiUdpListener {
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
}

impl RaiiUdpListener {
    pub fn new(port: u16,
               our_contact_info: Arc<Mutex<StaticContactInfo>>,
               our_public_key: PublicKey,
               event_tx: ::CrustEventSender,
               connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>,
               _bootstrap_cache: Arc<Mutex<BootstrapHandler>>,
               mc: Arc<MappingContext>)
               -> io::Result<RaiiUdpListener> {
        let udp_socket = try!(UdpSocket::bind(&format!("0.0.0.0:{}", port)[..]));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let cloned_stop_flag = stop_flag.clone();

        try!(udp_socket.set_read_timeout(Some(Duration::from_secs(UDP_READ_TIMEOUT_SECS))));
        let actual_port = try!(udp_socket.local_addr()).port();

        // TODO This will be very slow for production
        // Ask others for our UDP external addresses as they see us. No need to filter out the
        // Local addresses as they will be used by processes in LAN where TCP is disallowed.
        let mut addrs = Vec::new();
        if let Ok(MappedUdpSocket { endpoints, socket }) =
               MappedUdpSocket::map(try!(udp_socket.try_clone()), &mc).result_log() {
            addrs.extend(endpoints.into_iter().map(|ma| ma.addr));
            let local_addr = unwrap_result!(socket.local_addr());
            addrs.push(SocketAddr(local_addr));
        }

        unwrap_result!(our_contact_info.lock()).utp_custom_listeners.extend(addrs);

        let raii_joiner = RaiiThreadJoiner::new(thread!("RaiiUdpListener", move || {
            Self::run(our_contact_info,
                      our_public_key,
                      udp_socket,
                      event_tx,
                      cloned_stop_flag,
                      connection_map,
                      mc);
        }));

        Ok(RaiiUdpListener {
            stop_flag: stop_flag,
            _raii_joiner: raii_joiner,
        })
    }

    fn run(our_contact_info: Arc<Mutex<StaticContactInfo>>,
           our_public_key: PublicKey,
           udp_socket: UdpSocket,
           event_tx: ::CrustEventSender,
           stop_flag: Arc<AtomicBool>,
           connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>,
           mc: Arc<MappingContext>) {
        let mut read_buf = [0; 1024];

        while !stop_flag.load(Ordering::SeqCst) {
            if let Ok((bytes_read, peer_addr)) = udp_socket.recv_from(&mut read_buf) {
                if let Ok(msg) = deserialise::<ListenerRequest>(&read_buf[..bytes_read]) {
                    RaiiUdpListener::handle_request(msg,
                                                    &our_contact_info,
                                                    &udp_socket,
                                                    &our_public_key,
                                                    peer_addr,
                                                    &event_tx,
                                                    connection_map.clone(),
                                                    &mc);
                }
            }
        }
    }

    fn handle_request(msg: ListenerRequest,
                      our_contact_info: &Arc<Mutex<StaticContactInfo>>,
                      udp_socket: &UdpSocket,
                      our_public_key: &PublicKey,
                      peer_addr: net::SocketAddr,
                      event_tx: &::CrustEventSender,
                      connection_map: Arc<Mutex<HashMap<PeerId, Vec<Connection>>>>,
                      mc: &MappingContext) {
        match msg {
            ListenerRequest::Connect { our_info, .. } => {
                let their_info = our_info;
                let MappedUdpSocket { socket, endpoints } = {
                    match MappedUdpSocket::new(&mc).result_log() {
                        Ok(mapped_socket) => mapped_socket,
                        Err(_) => return,
                    }
                };

                let (our_priv_info, our_pub_info) = gen_rendezvous_info(endpoints);
                let connect_resp = ListenerResponse::Connect {
                    our_info: our_pub_info,
                    their_info: their_info.clone(),
                    pub_key: our_public_key.clone(),
                };

                if udp_socket.send_to(&unwrap_result!(serialise(&connect_resp)),
                                      peer_addr.clone())
                             .is_err() {
                    return;
                }

                let PunchedUdpSocket { socket, peer_addr } = {
                    match PunchedUdpSocket::punch_hole(socket, our_priv_info, their_info)
                              .result_log() {
                        Ok(punched_socket) => punched_socket,
                        Err(e) => return,
                    }
                };

                utp_rendezvous_connect(socket,
                                       peer_addr,
                                       UtpRendezvousConnectMode::BootstrapAccept,
                                       our_public_key.clone(),
                                       event_tx.clone(),
                                       connection_map.clone());
            }
        }
    }
}

impl Drop for RaiiUdpListener {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}
