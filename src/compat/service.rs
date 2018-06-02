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

use compat::{event_loop, CrustEventSender, EventLoop};
use compat::{ConnectionInfoResult, ConnectionMap, Event};
use error::CrustError;
use future_utils::{self, bi_channel, DropNotify};
use futures::unsync::mpsc;
use log::LogLevel;
use net::{service_discovery, ServiceDiscovery};
use priv_prelude::*;
#[cfg(test)]
use rust_sodium::crypto::box_::PublicKey;
use std;

pub trait FnBox {
    fn call_box(self: Box<Self>, state: &mut ServiceState);
}

impl<F: FnOnce(&mut ServiceState)> FnBox for F {
    #[cfg_attr(feature = "cargo-clippy", allow(boxed_local))]
    fn call_box(self: Box<Self>, state: &mut ServiceState) {
        (*self)(state)
    }
}

pub type ServiceCommand = Box<FnBox + Send>;

/// This type is a compatibility layer to provide a message-passing API over the underlying
/// futures-based implementation of Service.
pub struct Service {
    event_loop: EventLoop,
}

impl Service {
    /// Construct a service. `event_tx` is the sending half of the channel which crust will send
    /// notifications on.
    pub fn new(event_tx: CrustEventSender, our_uid: Uid, our_sk: SecretKey) -> Result<Service, CrustError> {
        let config = ConfigFile::open_default()?;
        Service::with_config(event_tx, config, our_uid, our_sk)
    }

    /// Constructs a service with the given config. User needs to create an asynchronous channel,
    /// and provide the sender half to this method. Receiver will receive all `Event`s from this
    /// library.
    pub fn with_config(
        event_tx: CrustEventSender,
        config: ConfigFile,
        our_uid: Uid,
        our_sk: SecretKey
    ) -> Result<Service, CrustError> {
        let event_loop_id = Some(format!("{:?}", our_uid));
        let event_loop = event_loop::spawn_event_loop(
            event_loop_id.as_ref().map(|s| s.as_ref()),
            event_tx,
            our_uid,
            our_sk,
            config.clone(),
        )?;
        event_loop.send(Box::new(move |state: &mut ServiceState| {
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
                    cm.whitelist_filter(&client_ips, &node_ips);
                    Ok(())
                })
            })
        }));
        Ok(Service { event_loop })
    }

    /// Enables service discovery during bootstrapping.
    pub fn start_service_discovery(&self) {
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                state.service_discovery_enabled = true;
            }));
    }

    /// Depending on given argument either starts *Crust* peer discovery on LAN (via UDP broadcast)
    /// or stops it.
    pub fn set_service_discovery_listen(&self, listen: bool) {
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
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
            }));
    }

    /// Depending on given argument either starts *Crust* bootstrap acceptor or stops it.
    pub fn set_accept_bootstrap(&self, accept: bool) -> Result<(), CrustError> {
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
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
                                        let _ = event_tx
                                            .send(Event::BootstrapAccept(their_uid, their_kind));
                                    }
                                    Ok(())
                                })
                                .infallible()
                        });
                    }
                } else {
                    let _ = state.bootstrap_acceptor.take();
                }
            }));
        Ok(())
    }

    /// Fetches given peer socket address.
    /// Blocks until address is retrieved.
    pub fn get_peer_socket_addr(&self, peer_uid: &Uid) -> Result<PaAddr, CrustError> {
        let peer_uid = *peer_uid;
        let (tx, rx) = std::sync::mpsc::channel::<Result<PaAddr, CrustError>>();
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                unwrap!(tx.send(state.cm.peer_addr(&peer_uid)));
            }));
        unwrap!(rx.recv())
    }

    /// Same as `get_peer_socket_addr()`, but it returns IP address instead.
    pub fn get_peer_ip_addr(&self, peer_uid: &Uid) -> Result<IpAddr, CrustError> {
        self.get_peer_socket_addr(peer_uid).map(|a| a.ip())
    }

    /// Checks if given peer is the one from hard coded contacts list.
    /// Blocks until response is received.
    pub fn is_peer_hard_coded(&self, peer_uid: &Uid) -> bool {
        let peer_uid = *peer_uid;
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                let config = state.service.config();
                let res = {
                    state
                        .cm
                        .peer_addr(&peer_uid)
                        .map(|peer_addr| {
                            config
                                .read()
                                .hard_coded_contacts
                                .iter()
                                .any(|peer| peer.addr.ip() == peer_addr.ip())
                        })
                        .unwrap_or(false)
                };
                unwrap!(tx.send(res));
            }));
        unwrap!(rx.recv())
    }

    /// Asynchronously starts bootstrapping to the network.
    /// Returns immediately.
    pub fn start_bootstrap(
        &self,
        blacklist: HashSet<PaAddr>,
        crust_user: CrustUser,
    ) -> Result<(), CrustError> {
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
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
                            let _ = cm.insert_peer(&handle, peer, addr);
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
            }));
        Ok(())
    }

    /// Cancels the bootstrap process.
    pub fn stop_bootstrap(&self) -> Result<(), CrustError> {
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                let _ = state.bootstrap_connect.take();
            }));
        Ok(())
    }

    /// Asynchronously starts listening for incoming connections.
    /// Returns immediately.
    pub fn start_listening(&self) -> Result<(), CrustError> {
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                if state.listeners.is_some() {
                    return;
                }

                let event_tx = state.event_tx.clone();
                let (drop_tx, drop_rx) = future_utils::drop_notify();
                state.listeners = Some(drop_tx);
                let f = {
                    state
                        .service
                        .start_listening()
                        .map_err(|e| error!("failed to start listener: {}", e))
                        .map(move |listener| {
                            let addr = listener.addr();
                            let _ = event_tx.send(Event::ListenerStarted(addr));
                            future::empty::<(), ()>().map(move |()| drop(listener))
                        })
                        .buffer_unordered(256)
                        .for_each(|()| Ok(()))
                        .until(drop_rx.infallible())
                        .map(|_unit_opt| ())
                };
                state.service.handle().spawn(f)
            }));
        Ok(())
    }

    /// Stops direct connection listener.
    pub fn stop_listening(&self) -> Result<(), CrustError> {
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                let _ = state.listeners.take();
            }));
        Ok(())
    }

    /// Fires event to start connection info preparation.
    /// Another event will be fired to `event_tx` to notify that info is ready.
    pub fn prepare_connection_info(&self, result_token: u32) {
        let (ci_channel1, ci_channel2) = bi_channel::unbounded();
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                state.spawn_connect(ci_channel1);
                let event_tx = state.event_tx.clone();
                let mut cm = state.cm.clone();
                let f = ci_channel2
                    .into_future()
                    .map_err(|(_e, _chann)| CrustError::PrepareConnectionInfo)
                    .and_then(|(our_conn_info_opt, ci_channel)| {
                        our_conn_info_opt
                            .ok_or(CrustError::PrepareConnectionInfo)
                            .map(move |conn_info| (conn_info, ci_channel))
                    })
                    .then(move |result| {
                        let result = match result {
                            Ok((our_conn_info, ci_channel)) => {
                                cm.insert_ci_channel(our_conn_info.connection_id, ci_channel);
                                Ok(our_conn_info)
                            }
                            Err(e) => Err(e),
                        };

                        let _ =
                            event_tx.send(Event::ConnectionInfoPrepared(ConnectionInfoResult {
                                result_token,
                                result,
                            }));
                        Ok(())
                    });
                state.service.handle().spawn(f);
            }));
    }

    /// Connect to a peer. To call this method you must follow these steps:
    ///  * Generate a `PrivConnectionInfo` via `Service::prepare_connection_info`.
    ///  * Create a `PubConnectionInfo` via `PrivConnectionInfo::to_pub_connection_info`.
    ///  * Swap `PubConnectionInfo`s out-of-band with the peer you are connecting to.
    ///  * Call `Service::connect` using your `PrivConnectionInfo` and the `PubConnectionInfo`
    ///    obtained from the peer
    pub fn connect(
        &self,
        our_ci: PubConnectionInfo,
        their_ci: PubConnectionInfo,
    ) -> Result<(), CrustError> {
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                if let Some(ci_chann) = state.cm.get_ci_channel(our_ci.connection_id) {
                    let _ = ci_chann.unbounded_send(their_ci);
                }
            }));
        Ok(())
    }

    /// Disconnect from the given peer and returns whether there was a connection at all.
    pub fn disconnect(&self, peer_uid: &Uid) -> bool {
        let peer_uid = *peer_uid;
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                unwrap!(tx.send(state.cm.remove(&peer_uid)));
            }));
        unwrap!(rx.recv())
    }

    /// Send data to a peer.
    pub fn send(&self, peer_uid: &Uid, msg: Vec<u8>, priority: Priority) -> Result<(), CrustError> {
        let peer_uid = *peer_uid;
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                unwrap!(tx.send(state.cm.send(&peer_uid, msg, priority)));
            }));
        unwrap!(rx.recv())
    }

    /// Check if we are connected to the given peer
    pub fn is_connected(&self, peer_uid: &Uid) -> bool {
        let peer_uid = *peer_uid;
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                unwrap!(tx.send(state.cm.contains_peer(&peer_uid)));
            }));
        unwrap!(rx.recv())
    }

    /// Returns our ID.
    pub fn id(&self) -> Uid {
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                unwrap!(tx.send(state.service.id()));
            }));
        unwrap!(rx.recv())
    }

    /// Checks if there are other crust on our LAN.
    pub fn has_peers_on_lan(&self) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                let handle = state.service.handle();
                let config = state.service.config();
                let sd_port = config
                    .read()
                    .service_discovery_port
                    .unwrap_or(::service::SERVICE_DISCOVERY_DEFAULT_PORT);
                let our_pk = state.service.public_key();
                let our_sk = state.service.private_key();
                let f = {
                    service_discovery::discover::<Vec<SocketAddr>>(handle, sd_port, our_pk, our_sk)
                        .into_future()
                        .map(|s| s.infallible())
                        .flatten_stream()
                        .first_ok()
                        .map(|_| ())
                        .map_err(|_| ())
                        .with_timeout(Duration::from_secs(1), handle)
                        .and_then(|res| res.ok_or(()))
                        .then(move |res| {
                            let _ = tx.send(res.is_ok());
                            Ok(())
                        })
                };
                handle.spawn(f);
            }));
        unwrap!(rx.recv())
    }

    /// Returns public key.
    #[cfg(test)]
    pub fn public_key(&self) -> PublicKey {
        let (tx, rx) = std::sync::mpsc::channel();
        self.event_loop
            .send(Box::new(move |state: &mut ServiceState| {
                unwrap!(tx.send(state.service.public_key()));
            }));
        unwrap!(rx.recv())
    }
}

pub struct ServiceState {
    service: ::Service,
    event_tx: CrustEventSender,
    cm: ConnectionMap,

    bootstrap_acceptor: Option<DropNotify>,
    bootstrap_connect: Option<DropNotify>,
    listeners: Option<DropNotify>,
    service_discovery: Option<ServiceDiscovery>,
    service_discovery_enabled: bool,
}

impl ServiceState {
    pub fn new(service: ::Service, event_tx: CrustEventSender) -> ServiceState {
        let cm = ConnectionMap::new(event_tx.clone());
        ServiceState {
            service,
            event_tx,
            cm,
            bootstrap_acceptor: None,
            bootstrap_connect: None,
            listeners: None,
            service_discovery: None,
            service_discovery_enabled: false,
        }
    }

    /// Spawns connection task that yields our connection info to provided conn info channel
    /// and waits for peer's connection info on the same channel.
    /// Emits `ConnectSuccess` and `ConnectFailure` events.
    fn spawn_connect(
        &mut self,
        ci_channel1: bi_channel::UnboundedBiChannel<PubConnectionInfo>,
    ) {
        let event_tx1 = self.event_tx.clone();
        let event_tx2 = event_tx1.clone();
        let cm = self.cm.clone();
        let handle = self.service.handle().clone();
        let (their_ci_tx, mut their_ci_rx) = mpsc::unbounded();
        let f = {
            let handle = handle.clone();
            self.service
                .connect(
                    ci_channel1.and_then(move |their_ci: PubConnectionInfo| {
                        unwrap!(their_ci_tx.clone().unbounded_send(their_ci.id));
                        Ok(their_ci)
                    }),
                )
                .map_err(move |e| {
                    error!("connection failed: {}", e);
                })
                .and_then(move |peer| {
                    let addr = {
                        peer.addr().map_err(|e| {
                            error!("failed to get address of peer we connected to: {}", e)
                        })
                    }?;
                    let _ = event_tx1.send(Event::ConnectSuccess(peer.uid()));
                    let _ = cm.insert_peer(&handle, peer, addr);
                    Ok(())
                })
                .or_else(move |_err| {
                    // if we know ID of the peer we were trying to connect with
                    if let Ok(Async::Ready(Some(peer_uid))) = their_ci_rx.poll() {
                        let _ = event_tx2.send(Event::ConnectFailure(peer_uid));
                    }
                    Ok(())
                })
        };
        handle.spawn(f);
    }
}

impl Drop for ServiceState {
    fn drop(&mut self) {
        self.cm.clear()
    }
}
