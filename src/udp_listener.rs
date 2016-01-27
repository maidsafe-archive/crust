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

use soket_addr::SocketAddr;

const UDP_READ_TIMEOUT_SECS: u64 = 2;

enum UdpListenerMsg {
    EchoExternalAddr,
    EchoExternalAddrResp {
        external_addr: SocketAddr,
    },
    ConnectRequest {
        connect_on: Vec<SocketAddr>,
        secret: [u8; 4],
    },
    ConnectResponse {
        connect_on: Vec<SocketAddr>,
        secret: [u8; 4],
        pub_key: PublicKey,
    },
}
pub struct UdpListener {
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
}

impl UdpListener {
    pub fn new(update_contact_info_tx: Sender<ASDFG>,
               event_tx: ::CrustEventSender,
               their_contact_infos: Vec<ContactInfo>)
               -> io::Result<UdpListener> {
        let udp_socket = try!(UdpSocket::bind("0.0.0.0:0"));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let cloned_stop_flag = stop_flag.clone();

        try!(udp_socket.set_read_timeout(Duration::from_secs(UDP_READ_TIMEOUT_SECS)));
        let port = try!(udp_socket.local_addr()).port();

        // Ask others for our UDP external addresses as they see us. No need to filter out the
        // Local addresses as they will be used by processes in LAN where TCP is disallowed.
        let echo_external_addr_request =
            unwrap_result!(serialise(&UdpListenerMsg::EchoExternalAddr));
        for their_contact_info in their_contact_infos {
            for udp_listener in their_contact_info.udp_listeners {
                let _ = udp_socket.send_to(&echo_external_addr_request, udp_listener);
            }
        }

        let raii_joiner = RaiiThreadJoiner::new(thread!("UdpListener", move || {
            run(udp_socket, event_tx, cloned_stop_flag);
        }));

        Ok(UdpListener {
            stop_flag: stop_flag,
            _raii_joiner: raii_joiner,
        })
    }

    fn run(udp_socket: UdpSocket,
           update_contact_info_tx: Sender<ASDFG>,
           event_tx: ::CrustEventSender,
           stop_flag: Acr<AtomicBool>) {
        let mut read_buf = [0; 1024];

        while !stop_flag.load(Ordering::SeqCst) {
            if let Ok((bytes_read, peer_addr)) = udp_socket.recv_from(&mut read_buf) {
                let msg = match deserialise::<UdpListenerMsg>(&read_buf[..bytes_read]) {
                    Ok(msg) => msg,
                    Err(_) => continue,
                };

                match msg {
                    UdpListenerMsg::EchoExternalAddr => {
                        let resp = UdpListenerMsg::EchoExternalAddrResp {
                            external_addr: SocketAddr(peer_addr.clone()),
                        };

                        let _ = udp_socket.send_to(&unwrap_result!(serialise(&resp)), peer_addr);
                    }
                    UdpListenerMsg::EchoExternalAddrResp { external_addr, } => {
                        if update_contact_info_tx.send(AppendUdpListener(external_addr)).is_err() {
                            break;
                        }
                    }
                    UdpListenerMsg::ConnectRequest { secret, contact_info } => {
                        // TODO blocking_get_mapped_udp_socket() should return the external address
                        // of the socket that it freshly spawned or (if it cannot because of say
                        // Zero-state etc.) Vector of all interface addresses. This should never be
                        // an option because then it is pretty useless.
                        if let Ok(res) =
                               blocking_get_mapped_udp_socket(rand::random(),
                                                              their_contact_infos.clone()) {
                            let connect_resp = UdpListenerMsg::ConnectResponse {
                                connect_on: res.1,
                                secret: secret,
                            };

                            if udp_socket.send_to(&unwrap_result!(&serialise(&connect_resp)),
                                                  peer_addr.clone())
                                         .is_err() {
                                continue;
                            }

                            if let Ok((socket, Ok(peer_addr))) =
                                   blocking_udp_punch_hole(res.0, secret, peer_addr) {
                                let connection = match udp_rendezvous_connect(socket,
                                                                              peer_addr,
                                                                              pub_key.clone()) {
                                    Ok(connection) => connection,
                                    Err(_) => continue,
                                };

                                let event = Event::NewConnection {
                                    their_pub_key: contact_info.pub_key,
                                    connection: Ok(connection),
                                };

                                if event_tx_to_acceptor.send(event).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    UdpListenerMsg::ConnectResponse { connect_on, secret, pub_key, } => {
                        if let Ok(res) =
                               blocking_get_mapped_udp_socket(rand::random(),
                                                              their_contact_infos.clone()) {
                            for peer_addr in connect_on {
                                let (socket, peer_addr) =
                                    match blocking_udp_punch_hole(res.0, secret, peer_addr) {
                                        Ok((socket, Ok(peer_addr))) => (socket, peer_addr),
                                        _ => continue,
                                    };

                                let connection = match udp_rendezvous_connect(socket,
                                                                              peer_addr,
                                                                              pub_key.clone()) {
                                    Ok(connection) => connection,
                                    Err(_) => continue,
                                };

                                let event = Event::NewConnection {
                                    their_pub_key: contact_info.pub_key,
                                    connection: Ok(connection),
                                };

                                if event_tx_to_acceptor.send(event).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Drop for UdpListener {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}
