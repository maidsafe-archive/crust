// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use compat::{ConnectionInfoResult, ConnectionMap, Event};
use compat::{CrustEventSender, EventLoop, event_loop};
use error::CrustError;
use future_utils::{self, DropNotify};
use log::LogLevel;

use net::{ServiceDiscovery, service_discovery};

use priv_prelude::*;
use std;

pub trait FnBox<UID: Uid> {
    fn call_box(self: Box<Self>, state: &mut ServiceState<UID>);
}

impl<UID: Uid, F: FnOnce(&mut ServiceState<UID>)> FnBox<UID> for F {
    fn call_box(self: Box<Self>, state: &mut ServiceState<UID>) {
        (*self)(state)
    }
}

pub type ServiceCommand<UID> = Box<FnBox<UID> + Send>;

/// This type is a compatibility layer to provide a message-passing API over the underlying
/// futures-based implementation of Service.
pub struct Service<UID: Uid> {
    event_loop: EventLoop<UID>,
}

impl<UID: Uid> Service<UID> {
    /// Construct a service. `event_tx` is the sending half of the channel which crust will send
    /// notifications on.
    pub fn new(event_tx: CrustEventSender<UID>, our_uid: UID) -> Result<Service<UID>, CrustError> {
        let config = ConfigFile::open_default()?;
        Service::with_config(event_tx, config, our_uid)
    }

    /// Constructs a service with the given config. User needs to create an asynchronous channel,
    /// and provide the sender half to this method. Receiver will receive all `Event`s from this
    /// library.
    pub fn with_config(
        event_tx: CrustEventSender<UID>,
        config: ConfigFile,
        our_uid: UID,
    ) -> Result<Service<UID>, CrustError> {
        let event_loop_id = Some(format!("{:?}", our_uid));
        let event_loop = event_loop::spawn_event_loop(
            event_loop_id.as_ref().map(|s| s.as_ref()),
            event_tx,
            our_uid,
            config.clone(),
        )?;
        event_loop.send(Box::new(move |state: &mut ServiceState<UID>| {
            let config_updates = state.service.config().observe();
            let cm = state.cm.clone();
            state.service.handle().spawn({
                config_updates.for_each(move |()| {
                    let client_ips = config.read().whitelisted_client_ips.clone();
                    let node_ips = config.read().whitelisted_node_ips.clone();
                    if node_ips.is_none() && client_ips.is_none() {
                        return Ok(());
                    }
                    let node_ips = node_ips.unwrap_or_default();
                    let client_ips = client_ips.unwrap_or_default();
                    cm.whitelist_filter(client_ips, node_ips);
                    Ok(())
                })
            })
        }));
        Ok(Service { event_loop })
    }

    pub fn start_service_discovery(&self) {
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                state.service_discovery_enabled = true;
            },
        ));
    }

    pub fn set_service_discovery_listen(&self, listen: bool) {
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                if !listen {
                    let _ = state.service_discovery.take();
                    return;
                }

                let sd = match state.service.start_service_discovery() {
                    Ok(sd) => sd,
                    Err(e) => {
                        error!("failed to start service discovery!: {}", e);
                        return;
                    }
                };
                state.service_discovery = Some(sd);
            },
        ));
    }

    pub fn set_accept_bootstrap(&self, accept: bool) -> Result<(), CrustError> {
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                if accept {
                    if state.bootstrap_acceptor.is_none() {
                        let handle0 = state.service.handle().clone();
                        let handle1 = state.service.handle().clone();
                        let (drop_tx, drop_rx) = future_utils::drop_notify();
                        state.bootstrap_acceptor = Some(drop_tx);
                        let acceptor = state.service.bootstrap_acceptor();
                        let cm = state.cm.clone();
                        let event_tx = state.event_tx.clone();
                        handle0.spawn({
                            acceptor
                                .log_errors(LogLevel::Info, "accepting bootstrap connection")
                                .until(drop_rx)
                                .for_each(move |peer| {
                                    let their_uid = peer.uid();
                                    let their_kind = peer.kind();
                                    let their_addr = match peer.addr() {
                                        Ok(addr) => addr,
                                        Err(e) => {
                                            error!(
                                                "error getting address of bootstrapping peer: {}",
                                                e
                                            );
                                            return Ok(());
                                        }
                                    };
                                    if cm.insert_peer(&handle1, peer, their_addr) {
                                        let _ = event_tx.send(Event::BootstrapAccept(
                                            their_uid,
                                            their_kind,
                                        ));
                                    }
                                    Ok(())
                                })
                                .infallible()
                        });
                    }
                } else {
                    let _ = state.bootstrap_acceptor.take();
                }
            },
        ));
        Ok(())
    }

    pub fn get_peer_socket_addr(&self, peer_uid: &UID) -> Result<SocketAddr, CrustError> {
        let peer_uid = *peer_uid;
        let (tx, rx) = std::sync::mpsc::channel::<Result<SocketAddr, CrustError>>();
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                unwrap!(tx.send(state.cm.peer_addr(&peer_uid)));
            },
        ));
        unwrap!(rx.recv())
    }

    pub fn get_peer_ip_addr(&self, peer_uid: &UID) -> Result<IpAddr, CrustError> {
        self.get_peer_socket_addr(peer_uid).map(|a| a.ip())
    }

    pub fn is_peer_hard_coded(&self, peer_uid: &UID) -> bool {
        let peer_uid = *peer_uid;
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                let config = state.service.config();
                let res = {
                    state
                        .cm
                        .peer_addr(&peer_uid)
                        .map(|peer_addr| {
                            config.read().hard_coded_contacts.iter().any(|addr| {
                                addr.ip() == peer_addr.ip()
                            })
                        })
                        .unwrap_or(false)
                };
                unwrap!(tx.send(res));
            },
        ));
        unwrap!(rx.recv())
    }

    pub fn start_bootstrap(
        &self,
        blacklist: HashSet<SocketAddr>,
        crust_user: CrustUser,
    ) -> Result<(), CrustError> {
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                let (drop_tx, drop_rx) = future_utils::drop_notify();
                let use_service_discovery = state.service_discovery_enabled;
                state.bootstrap_connect = Some(drop_tx);
                let cm = state.cm.clone();
                let event_tx = state.event_tx.clone();
                let f = {
                    let handle = state.service.handle().clone();
                    state
                        .service
                        .bootstrap(blacklist, use_service_discovery, crust_user)
                        .map_err(|e| error!("bootstrap failed: {}", e))
                        .and_then(move |peer| {
                            let addr = {
                                peer.addr().map_err(|e| {
                                    error!(
                                        "failed to get address of peer we bootstrapped to: {}",
                                        e
                                    )
                                })
                            }?;
                            let uid = peer.uid();
                            cm.insert_peer(&handle, peer, addr);
                            Ok((addr, uid))
                        })
                        .then(move |res| {
                            let event = match res {
                                Ok((addr, uid)) => Event::BootstrapConnect(uid, addr),
                                Err(()) => Event::BootstrapFailed,
                            };
                            let _ = event_tx.send(event);
                            Ok(())
                        })
                        .until(drop_rx.infallible())
                        .map(|_| ())
                };
                state.service.handle().spawn(f);
            },
        ));
        Ok(())
    }

    pub fn stop_bootstrap(&self) -> Result<(), CrustError> {
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                let _ = state.bootstrap_connect.take();
            },
        ));
        Ok(())
    }

    pub fn start_listening_tcp(&self) -> Result<(), CrustError> {
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                if state.tcp_listener.is_some() {
                    return;
                }

                let event_tx = state.event_tx.clone();
                let (drop_tx, drop_rx) = future_utils::drop_notify();
                state.tcp_listener = Some(drop_tx);
                let f = {
                    state
                        .service
                        .start_listener()
                        .map_err(|e| error!("failed to start listener: {}", e))
                        .and_then(move |listener| {
                            let port = listener.addr().port();
                            let _ = event_tx.send(Event::ListenerStarted(port));
                            future::empty::<(), ()>()
                    .map(move |()| drop(listener))
                        })
                        .until(drop_rx.infallible())
                        .map(|_unit_opt| ())
                };
                state.service.handle().spawn(f)
            },
        ));
        Ok(())
    }

    pub fn stop_tcp_listener(&self) -> Result<(), CrustError> {
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                let _ = state.tcp_listener.take();
            },
        ));
        Ok(())
    }

    pub fn prepare_connection_info(&self, result_token: u32) {
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                let event_tx = state.event_tx.clone();
                let f = {
                    state.service.prepare_connection_info().then(move |result| {
                        let _ = event_tx.send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                            result_token,
                            result,
                        }));
                        Ok(())
                    })
                };
                state.service.handle().spawn(f);
            },
        ));
    }

    /// Connect to a peer. To call this method you must follow these steps:
    ///  * Generate a `PrivConnectionInfo` via `Service::prepare_connection_info`.
    ///  * Create a `PubConnectionInfo` via `PrivConnectionInfo::to_pub_connection_info`.
    ///  * Swap `PubConnectionInfo`s out-of-band with the peer you are connecting to.
    ///  * Call `Service::connect` using your `PrivConnectionInfo` and the `PubConnectionInfo`
    ///    obtained from the peer
    pub fn connect(
        &self,
        our_ci: PrivConnectionInfo<UID>,
        their_ci: PubConnectionInfo<UID>,
    ) -> Result<(), CrustError> {
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                let uid = their_ci.id;
                let cm = state.cm.clone();
                let event_tx = state.event_tx.clone();
                let f = {
                    let handle = state.service.handle().clone();
                    state
                        .service
                        .connect(our_ci, their_ci)
                        .map_err(move |e| {
                            error!("connection to {:?} failed: {}", uid, e);
                        })
                        .and_then(move |peer| {
                            let addr = {
                                peer.addr().map_err(|e| {
                                    error!("failed to get address of peer we connected to: {}", e)
                                })
                            }?;
                            cm.insert_peer(&handle, peer, addr);
                            Ok(())
                        })
                        .then(move |res| {
                            let event = match res {
                                Ok(()) => Event::ConnectSuccess(uid),
                                Err(()) => Event::ConnectFailure(uid),
                            };
                            let _ = event_tx.send(event);
                            Ok(())
                        })
                };
                state.service.handle().spawn(f);
            },
        ));
        Ok(())
    }

    /// Disconnect from the given peer and returns whether there was a connection at all.
    pub fn disconnect(&self, peer_uid: &UID) -> bool {
        let peer_uid = *peer_uid;
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                unwrap!(tx.send(state.cm.remove(&peer_uid)));
            },
        ));
        unwrap!(rx.recv())
    }

    /// Send data to a peer.
    pub fn send(&self, peer_uid: &UID, msg: Vec<u8>, priority: Priority) -> Result<(), CrustError> {
        let peer_uid = *peer_uid;
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                unwrap!(tx.send(state.cm.send(&peer_uid, msg, priority)));
            },
        ));
        unwrap!(rx.recv())
    }

    /// Check if we are connected to the given peer
    pub fn is_connected(&self, peer_uid: &UID) -> bool {
        let peer_uid = *peer_uid;
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                unwrap!(tx.send(state.cm.contains_peer(&peer_uid)));
            },
        ));
        unwrap!(rx.recv())
    }

    /// Returns our ID.
    pub fn id(&self) -> UID {
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                unwrap!(tx.send(state.service.id()));
            },
        ));
        unwrap!(rx.recv())
    }

    /// Checks if there are other crust on our LAN.
    pub fn has_peers_on_lan(&self) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop.send(Box::new(
            move |state: &mut ServiceState<UID>| {
                let handle = state.service.handle();
                let config = state.service.config();
                let sd_port = config.read().service_discovery_port.unwrap_or(
                    ::service::SERVICE_DISCOVERY_DEFAULT_PORT,
                );
                let f = {
                    service_discovery::discover::<Vec<SocketAddr>>(&handle, sd_port)
                        .into_future()
                        .map(|s| s.infallible())
                        .flatten_stream()
                        .first_ok()
                        .map(|_| ())
                        .map_err(|_| ())
                        .with_timeout(&handle, Duration::from_secs(1), ())
                        .then(move |res| {
                            let _ = tx.send(res.is_ok());
                            Ok(())
                        })
                };
                handle.spawn(f);
            },
        ));
        unwrap!(rx.recv())
    }
}

pub struct ServiceState<UID: Uid> {
    service: ::Service<UID>,
    event_tx: CrustEventSender<UID>,
    cm: ConnectionMap<UID>,

    bootstrap_acceptor: Option<DropNotify>,
    bootstrap_connect: Option<DropNotify>,
    tcp_listener: Option<DropNotify>,
    service_discovery: Option<ServiceDiscovery>,
    service_discovery_enabled: bool,
}

impl<UID: Uid> ServiceState<UID> {
    pub fn new(service: ::Service<UID>, event_tx: CrustEventSender<UID>) -> ServiceState<UID> {
        let cm = ConnectionMap::new(event_tx.clone());
        ServiceState {
            service: service,
            event_tx: event_tx,
            cm: cm,
            bootstrap_acceptor: None,
            bootstrap_connect: None,
            tcp_listener: None,
            service_discovery: None,
            service_discovery_enabled: false,
        }
    }
}

impl<UID: Uid> Drop for ServiceState<UID> {
    fn drop(&mut self) {
        self.cm.clear()
    }
}
