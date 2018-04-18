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

use config::PeerInfo;
use future_utils::bi_channel;
use futures::sync::mpsc::UnboundedReceiver;
use net::{self, Acceptor, BootstrapAcceptor, Demux, Listener, ServiceDiscovery};
use net::peer::BootstrapRequest;
use p2p::{self, P2p};
use priv_prelude::*;
use rand::{self, Rng};
use rust_sodium::crypto::box_::{gen_keypair, PublicKey, SecretKey};

pub const SERVICE_DISCOVERY_DEFAULT_PORT: u16 = 5483;

/// The main entry point to Crust.
///
/// Use `Service` to accept incoming connections and to connect to remote peers.
/// There are two methods to initialize connections: `connect()` and `bootstrap()`.
/// Call `start_listener()` to accept connections.
///
/// By default no one can bootstrap off the listener, meaning no one can
/// connect to you with `bootstrap()`. To enable bootstrapping call
/// `bootstrap_acceptor()`.
///
/// `Service` provides futures based API compatible with [Tokio](https://tokio.rs/) event loop.
///
/// Once you are connected, use [Peer](struct.Peer.html) to exchange data.
pub struct Service<UID: Uid> {
    handle: Handle,
    config: ConfigFile,
    our_uid: UID,
    listeners: Acceptor,
    demux: Demux<UID>,
    p2p: P2p,
    our_pk: PublicKey,
    our_sk: SecretKey,
    bootstrap_cache: BootstrapCache,
}

impl<UID: Uid> Service<UID> {
    /// Create a new `Service` with the default config.
    pub fn new(handle: &Handle, our_uid: UID) -> BoxFuture<Service<UID>, CrustError> {
        let try = || -> Result<_, CrustError> {
            Ok(Service::with_config(
                handle,
                ConfigFile::open_default()?,
                our_uid,
            ))
        };
        future::result(try()).flatten().into_boxed()
    }

    /// Create a new `Service` with the given configuration.
    pub fn with_config(
        handle: &Handle,
        config: ConfigFile,
        our_uid: UID,
    ) -> BoxFuture<Service<UID>, CrustError> {
        let p2p = configure_nat_traversal(&config);
        let handle = handle.clone();

        let (our_pk, our_sk) = gen_keypair();
        let anon_decrypt_ctx = CryptoContext::anonymous_decrypt(our_pk, our_sk.clone());

        let bootstrap_cache = try_bfut!(make_bootstrap_cache(&config));
        let (listeners, socket_incoming) = Acceptor::new(
            &handle,
            p2p.clone(),
            anon_decrypt_ctx.clone(),
            our_sk.clone(),
        );
        let demux = Demux::new(&handle, socket_incoming, anon_decrypt_ctx, &bootstrap_cache);

        future::ok(Service {
            handle,
            config,
            our_uid,
            listeners,
            demux,
            p2p,
            our_pk,
            our_sk,
            bootstrap_cache,
        }).into_boxed()
    }

    /// Get a handle to the service's config file.
    pub fn config(&self) -> ConfigFile {
        self.config.clone()
    }

    /// Bootstrap to the network.
    ///
    /// Bootstrap concept is interchangeable with "connect". Except in context
    /// of Crust bootstrapping is more powerful than a simple `connect()`.
    /// `bootstrap()` will try to connect to all peers that are specified
    /// in config (`hard_coded_contacts`) or were cached.
    ///
    /// Returns a future that resolves to the first connected peer.
    pub fn bootstrap(
        &mut self,
        blacklist: HashSet<PaAddr>,
        use_service_discovery: bool,
        crust_user: CrustUser,
    ) -> BoxFuture<Peer<UID>, BootstrapError> {
        remove_rendezvous_servers(&self.p2p, &blacklist);
        let (current_addrs, _) = self.listeners.addresses();
        let ext_reachability = match crust_user {
            CrustUser::Node => ExternalReachability::Required {
                direct_listeners: current_addrs
                    .into_iter()
                    .map(|addr| PeerInfo::new(addr, self.our_pk))
                    .collect(),
            },
            CrustUser::Client => ExternalReachability::NotRequired,
        };
        let request = BootstrapRequest {
            uid: self.our_uid,
            name_hash: self.config.network_name_hash(),
            ext_reachability,
            their_pk: self.our_pk,
        };
        net::bootstrap(
            &self.handle,
            request,
            blacklist,
            use_service_discovery,
            &self.config,
            self.our_sk.clone(),
            &self.bootstrap_cache,
        )
    }

    /// Start a bootstrap acceptor. The returned `BootstrapAcceptor` can be used to receive peers
    /// who are bootstrapping to us. It can be dropped again to re-disable accepting bootstrapping
    /// peers.
    pub fn bootstrap_acceptor(&mut self) -> BootstrapAcceptor<UID> {
        self.demux
            .bootstrap_acceptor(&self.config, self.our_uid, self.our_sk.clone())
    }

    /// Start listening for incoming connections. The address/port to listen on is configured
    /// through the configuration file. The returned `Listener`s can be queried for their
    /// address, drop a `Listener` to stop listening on its address. The stream will end once all
    /// configured listeners have been returned.
    pub fn start_listening(&self) -> BoxStream<Listener, CrustError> {
        let addrs = self.config.listen_addresses();
        let futures = addrs.iter().map(|addr| {
            self.listeners
                .listener::<UID>(addr)
                .map_err(CrustError::StartListener)
        });
        stream::futures_unordered(futures).into_boxed()
    }

    /// Perform a p2p connection to a peer. Bidirectional channel is used to exchange connection
    /// info with remote peer.
    pub fn connect<C>(&self, ci_channel: C) -> BoxFuture<Peer<UID>, CrustError>
    where
        C: Stream<Item = PubConnectionInfo<UID>>,
        C: Sink<SinkItem = PubConnectionInfo<UID>>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static,
    {
        let config = self.config.clone();
        let demux = self.demux.clone();
        self.prepare_connection_info()
            .and_then(move |our_info| {
                let (ci_tx, ci_rx) = ci_channel.split();
                ci_tx
                    .send(our_info.to_pub_connection_info())
                    .map_err(|_e| ConnectError::ExchangeConnectionInfo)
                    .while_driving(demux.connect(
                        config.network_name_hash(),
                        our_info,
                        ci_rx,
                        &config,
                    ))
                    .map_err(|(e, _connect)| CrustError::ConnectError(e))
                    .and_then(|(_ci_tx, connect)| connect.map_err(CrustError::ConnectError))
            })
            .into_boxed()
    }

    /// The returned `ServiceDiscovery` advertises the existence of this peer to any other peers on
    /// the local network (via udp broadcast).
    pub fn start_service_discovery(&self) -> io::Result<ServiceDiscovery> {
        let (current_addrs, addrs_rx) = self.listeners.addresses();
        ServiceDiscovery::new(
            &self.handle,
            &self.config,
            &current_addrs,
            addrs_rx,
            self.our_pk,
        )
    }

    /// Return the set of all addresses that we are currently listening for incoming connections
    /// on. Also returns a channel that can be used to monitor when this set changes.
    pub fn addresses(&self) -> (HashSet<PaAddr>, UnboundedReceiver<HashSet<PaAddr>>) {
        self.listeners.addresses()
    }

    /// Get our ID.
    pub fn id(&self) -> UID {
        self.our_uid
    }

    /// Get the tokio `Handle` that this service is using.
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Get the handle to the `p2p` library config used by this service.
    pub fn p2p_config(&self) -> &P2p {
        &self.p2p
    }

    /// Returns service public key.
    pub fn public_key(&self) -> PublicKey {
        self.our_pk
    }

    /// Returns service private key.
    pub fn private_key(&self) -> SecretKey {
        self.our_sk.clone()
    }

    #[cfg(test)]
    pub fn bootstrap_cache(&self) -> BootstrapCache {
        self.bootstrap_cache.clone()
    }

    /// Prepare a connection info. This is the first step to doing a p2p connection to a peer. Both
    /// peers must call `prepare_connection_info`, use the returned `PrivConnectionInfo` to
    /// generate a `PubConnectionInfo`, trade `PubConnectionInfo`s using some out-of-channel, then
    /// call connect simultaneously using each other's `PubConnectionInfo` and their own
    /// `PrivConnectionInfo`.
    /// Note, that loopback addresses are filtered out.
    fn prepare_connection_info(&self) -> BoxFuture<PrivConnectionInfo<UID>, CrustError> {
        let (direct_addrs, _) = self.listeners.addresses();
        let direct_addrs = direct_addrs
            .into_iter()
            .filter(|addr| !addr.ip().is_loopback())
            .collect();
        let priv_conn_info = PrivConnectionInfo {
            connection_id: rand::thread_rng().gen(),
            id: self.our_uid,
            for_direct: direct_addrs,
            p2p_conn_info: None,
            our_pk: self.our_pk,
            our_sk: self.our_sk.clone(),
        };

        if self.listeners.has_public_addrs() {
            future::ok(priv_conn_info).into_boxed()
        } else {
            self.with_p2p_connection_info(priv_conn_info)
        }
    }

    /// Constructs private connection info with p2p info returned from `p2p` crate.
    /// p2p info is used for rendezvous connections - hole punching.
    fn with_p2p_connection_info(
        &self,
        mut priv_conn_info: PrivConnectionInfo<UID>,
    ) -> BoxFuture<PrivConnectionInfo<UID>, CrustError> {
        let (ch1, ch2) = bi_channel::unbounded();
        let conn_rx =
            net::peer::start_rendezvous_connect(&self.handle, &self.config, ch2, &self.p2p);

        ch1.into_future()
            .and_then(move |(conn_info_opt, chann)| {
                priv_conn_info.p2p_conn_info = conn_info_opt.and_then(|raw_info| {
                    Some(P2pConnectionInfo {
                        our_info: raw_info,
                        rendezvous_channel: chann,
                        connection_rx: conn_rx,
                    })
                });
                Ok(priv_conn_info)
            })
            .map_err(|(e, _stream)| e)
            .infallible()
            .into_boxed()
    }
}

fn configure_nat_traversal(config: &ConfigFile) -> P2p {
    let p2p = P2p::default();
    let force_use_local_port = config.read().force_acceptor_port_in_ext_ep;
    p2p.set_force_use_local_port(force_use_local_port);
    set_rendezvous_servers(&p2p, config);
    p2p.disable_igd_for_rendezvous();
    p2p
}

fn set_rendezvous_servers(p2p: &P2p, config: &ConfigFile) {
    let hard_coded_contacts = &config.read().hard_coded_contacts;
    for peer in hard_coded_contacts {
        match peer.addr {
            PaAddr::Tcp(addr) => {
                p2p.add_tcp_traversal_server(&p2p::PeerInfo::new(addr, peer.pub_key));
            }
            PaAddr::Utp(addr) => {
                p2p.add_udp_traversal_server(&p2p::PeerInfo::new(addr, peer.pub_key));
            }
        }
    }
}

fn remove_rendezvous_servers(p2p: &P2p, addrs: &HashSet<PaAddr>) {
    for addr in addrs {
        match *addr {
            PaAddr::Tcp(addr) => p2p.remove_tcp_traversal_server(addr),
            PaAddr::Utp(addr) => p2p.remove_udp_traversal_server(addr),
        }
    }
}

fn make_bootstrap_cache(config: &ConfigFile) -> Result<BootstrapCache, CrustError> {
    let bootstrap_cache_name = config.read().bootstrap_cache_name.clone();
    let cache_file = bootstrap_cache_name.as_ref().map(|s| s.as_os_str());
    let bootstrap_cache = BootstrapCache::new(cache_file).map_err(CrustError::ReadBootstrapCache)?;
    bootstrap_cache.read_file();
    Ok(bootstrap_cache)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructs peer info with given address and random public key.
    /// Usable in cases when public key is not used and we just want to get `PeerInfo`.
    macro_rules! peer_addr {
        ($addr:pat) => {
            {
                p2p::PeerInfo::with_rand_key(addr!($addr))
            }
        };
    }

    mod set_rendezvous_servers {
        use super::*;
        use config::PeerInfo;

        #[test]
        fn it_sets_hard_coded_tcp_contacts_as_rendezvous_servers() {
            let config = unwrap!(ConfigFile::new_temporary());
            unwrap!(config.write()).hard_coded_contacts = vec![
                PeerInfo::with_rand_key(tcp_addr!("1.2.3.4:4000")),
                PeerInfo::with_rand_key(tcp_addr!("1.2.3.5:5000")),
            ];
            let p2p = P2p::default();

            set_rendezvous_servers(&p2p, &config);

            let servers = p2p.tcp_traversal_servers().addrs_snapshot();
            assert!(servers.contains(&addr!("1.2.3.4:4000")));
            assert!(servers.contains(&addr!("1.2.3.5:5000")));
        }

        #[test]
        fn it_sets_hard_coded_utp_contacts_as_rendezvous_servers() {
            let config = unwrap!(ConfigFile::new_temporary());
            unwrap!(config.write()).hard_coded_contacts = vec![
                PeerInfo::with_rand_key(utp_addr!("1.2.3.4:4000")),
                PeerInfo::with_rand_key(utp_addr!("1.2.3.5:5000")),
            ];
            let p2p = P2p::default();

            set_rendezvous_servers(&p2p, &config);

            let servers = p2p.udp_traversal_servers().addrs_snapshot();
            assert!(servers.contains(&addr!("1.2.3.4:4000")));
            assert!(servers.contains(&addr!("1.2.3.5:5000")));
        }
    }

    mod remove_rendezvous_servers {
        use super::*;

        #[test]
        fn it_removes_specified_rendezvous_servers_from_global_list() {
            let p2p = P2p::default();
            p2p.add_tcp_traversal_server(&peer_addr!("1.2.3.4:4000"));
            p2p.add_udp_traversal_server(&peer_addr!("1.2.3.5:5000"));

            let rm_servers: HashSet<PaAddr> =
                vec![tcp_addr!("1.2.3.4:4000"), utp_addr!("1.2.3.5:5000")]
                    .iter()
                    .cloned()
                    .collect();
            remove_rendezvous_servers(&p2p, &rm_servers);

            let servers = p2p.tcp_traversal_servers().snapshot();
            assert!(servers.is_empty());
            let servers = p2p.udp_traversal_servers().snapshot();
            assert!(servers.is_empty());
        }
    }

    mod configure_nat_traversal {
        use super::*;

        #[test]
        fn it_returns_p2p_instance_with_igd_for_rendezvous_disabled() {
            let config = unwrap!(ConfigFile::new_temporary());
            let p2p = configure_nat_traversal(&config);

            assert!(!p2p.is_igd_enabled_for_rendezvous());
        }
    }

    mod service {
        use super::*;
        use tokio_core::reactor::Core;
        use util;

        mod prepare_connection_info {
            use super::*;

            #[test]
            fn it_does_not_include_loopback_address() {
                let mut evloop = unwrap!(Core::new());
                let handle = evloop.handle();
                let config = unwrap!(ConfigFile::new_temporary());
                unwrap!(config.write()).listen_addresses = vec![tcp_addr!("0.0.0.0:0")];

                let prep_conn_info = Service::with_config(&handle, config, util::random_id())
                    .and_then(|service| {
                        service
                            .start_listening()
                            .collect()
                            .map(|listeners| (service, listeners))
                    })
                    .and_then(|(service, _listeners)| service.prepare_connection_info());
                let conn_info = unwrap!(evloop.run(prep_conn_info));

                assert!(
                    conn_info
                        .for_direct
                        .iter()
                        .all(|addr| !addr.ip().is_loopback())
                );
            }
        }
    }
}
