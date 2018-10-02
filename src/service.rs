// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use config::PeerInfo;
use future_utils::bi_channel;
use futures::sync::mpsc::UnboundedReceiver;
use net::peer::BootstrapRequest;
use net::{self, Acceptor, BootstrapAcceptor, Demux, Listener, ServiceDiscovery};
use p2p::{self, NatType, P2p};
use priv_prelude::*;
use rand::{self, Rng};
use serde_json;
use std::fs::File;

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
pub struct Service {
    handle: Handle,
    config: ConfigFile,
    listeners: Acceptor,
    demux: Demux,
    p2p: P2p,
    our_sk: SecretEncryptKey,
    our_pk: PublicEncryptKey,
    bootstrap_cache: BootstrapCache,
}

impl Service {
    /// Create a new `Service` with the default config.
    pub fn new(
        handle: &Handle,
        our_sk: SecretEncryptKey,
        our_pk: PublicEncryptKey,
    ) -> BoxFuture<Service, CrustError> {
        let try = || -> Result<_, CrustError> {
            Ok(Service::with_config(
                handle,
                ConfigFile::open_default()?,
                our_sk,
                our_pk,
            ))
        };
        future::result(try()).flatten().into_boxed()
    }

    /// Create a new `Service` with the given configuration.
    pub fn with_config(
        handle: &Handle,
        config: ConfigFile,
        our_sk: SecretEncryptKey,
        our_pk: PublicEncryptKey,
    ) -> BoxFuture<Service, CrustError> {
        let p2p = configure_nat_traversal(&config);
        let handle = handle.clone();

        let bootstrap_cache = try_bfut!(make_bootstrap_cache(&config));
        let (listeners, socket_incoming) =
            Acceptor::new(&handle, p2p.clone(), our_sk.clone(), our_pk);
        let demux = Demux::new(&handle, socket_incoming, &bootstrap_cache);

        try_bfut!(try_write_encryption_keys(&config, &our_pk));

        future::ok(Service {
            handle,
            config,
            listeners,
            demux,
            p2p,
            our_sk,
            our_pk,
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
    ) -> BoxFuture<Peer, BootstrapError> {
        remove_rendezvous_servers(&self.p2p, &blacklist);
        let (current_addrs, _) = self.listeners.addresses();
        let ext_reachability = match crust_user {
            CrustUser::Node => ExternalReachability::Required {
                direct_listeners: current_addrs
                    .into_iter()
                    .map(|addr| PeerInfo::new(addr, self.public_id()))
                    .collect(),
            },
            CrustUser::Client => ExternalReachability::NotRequired,
        };
        let request = BootstrapRequest {
            name_hash: self.config.network_name_hash(),
            ext_reachability,
            client_uid: self.public_id(),
        };
        net::bootstrap(
            &self.handle,
            request,
            blacklist,
            use_service_discovery,
            &self.config,
            &self.our_sk,
            &self.our_pk,
            &self.bootstrap_cache,
        )
    }

    /// Start a bootstrap acceptor. The returned `BootstrapAcceptor` can be used to receive peers
    /// who are bootstrapping to us. It can be dropped again to re-disable accepting bootstrapping
    /// peers.
    pub fn bootstrap_acceptor(&mut self) -> BootstrapAcceptor {
        self.demux
            .bootstrap_acceptor(&self.config, self.public_id())
    }

    /// Start listening for incoming connections. The address/port to listen on is configured
    /// through the configuration file. The returned `Listener`s can be queried for their
    /// address, drop a `Listener` to stop listening on its address. The stream will end once all
    /// configured listeners have been returned.
    pub fn start_listening(&self) -> BoxStream<Listener, CrustError> {
        let addrs = self.config.listen_addresses();
        let futures = addrs.iter().map(|addr| {
            self.listeners
                .listener(addr)
                .map_err(CrustError::StartListener)
        });
        stream::futures_unordered(futures).into_boxed()
    }

    /// Perform a p2p connection to a peer. Bidirectional channel is used to exchange connection
    /// info with remote peer.
    pub fn connect<C>(&self, ci_channel: C) -> BoxFuture<Peer, CrustError>
    where
        C: Stream<Item = PubConnectionInfo>,
        C: Sink<SinkItem = PubConnectionInfo>,
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
                    )).map_err(|(e, _connect)| CrustError::ConnectError(e.to_string()))
                    .and_then(|(_ci_tx, connect)| {
                        connect.map_err(|e| CrustError::ConnectError(e.to_string()))
                    })
            }).into_boxed()
    }

    /// Attempt multiple connections in parallel and return info about all of them.
    #[cfg(feature = "connections_info")]
    pub fn connect_all<C>(
        &self,
        ci_channel: C,
    ) -> BoxStream<ConnectionResult, SingleConnectionError>
    where
        C: Stream<Item = PubConnectionInfo>,
        C: Sink<SinkItem = PubConnectionInfo>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static,
    {
        let config = self.config.clone();
        let demux = self.demux.clone();
        self.prepare_connection_info()
            .map_err(|e| panic!(e)) // TODO(povilas): fix me
            .and_then(move |our_info| {
                let (ci_tx, ci_rx) = ci_channel.split();
                ci_tx
                    .send(our_info.to_pub_connection_info())
                    .map_err(|_e| SingleConnectionError::DeadChannel)
                    .while_driving(future::ok(demux.connect_all(
                        our_info,
                        ci_rx,
                        &config,
                    ))).map_err(|(e, _connect)| e)
                    .and_then(|(_ci_tx, connect)| connect)
            }).flatten_stream().into_boxed()
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
            self.public_id(),
        )
    }

    /// Return the set of all addresses that we are currently listening for incoming connections
    /// on. Also returns a channel that can be used to monitor when this set changes.
    pub fn addresses(&self) -> (HashSet<PaAddr>, UnboundedReceiver<HashSet<PaAddr>>) {
        self.listeners.addresses()
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
    pub fn public_id(&self) -> PublicEncryptKey {
        self.our_pk
    }

    /// Returns service private key.
    pub fn secret_id(&self) -> SecretEncryptKey {
        self.our_sk.clone()
    }

    #[cfg(test)]
    pub fn bootstrap_cache(&self) -> BootstrapCache {
        self.bootstrap_cache.clone()
    }

    /// Start hole punching techniques to identify NAT (Network Address Translation) type.
    pub fn probe_nat(&self) -> BoxFuture<NatType, CrustError> {
        let p2p = P2p::default();
        set_rendezvous_servers(&p2p, &self.config);
        p2p.disable_igd();
        p2p.disable_igd_for_rendezvous();

        let bind_addr = try_bfut!(
            UdpSocket::bind_reusable(&addr!("0.0.0.0:0"), &self.handle)
                .and_then(|socket| socket.local_addr())
                .map_err(CrustError::Io)
        );
        p2p::rendezvous_addr(p2p::Protocol::Udp, &bind_addr, &self.handle, &p2p)
            .then(|res| match res {
                Err(e) => e.unpredictable_ports().ok_or(e),
                Ok((_public_addr, nat_type)) => Ok(nat_type),
            }).map_err(CrustError::ProbeNatError)
            .into_boxed()
    }

    /// Prepare a connection info. This is the first step to doing a p2p connection to a peer. Both
    /// peers must call `prepare_connection_info`, use the returned `PrivConnectionInfo` to
    /// generate a `PubConnectionInfo`, trade `PubConnectionInfo`s using some out-of-channel, then
    /// call connect simultaneously using each other's `PubConnectionInfo` and their own
    /// `PrivConnectionInfo`.
    fn prepare_connection_info(&self) -> BoxFuture<PrivConnectionInfo, CrustError> {
        let (direct_addrs, _) = self.listeners.addresses();
        let priv_conn_info = PrivConnectionInfo {
            connection_id: rand::thread_rng().gen(),
            our_uid: self.public_id(),
            for_direct: direct_addrs.into_iter().collect(),
            p2p_conn_info: None,
            our_pk: self.public_id(),
            our_sk: self.our_sk.clone(),
        };

        if self.listeners.has_public_addrs() || self.config.rendezvous_connections_disabled() {
            future::ok(priv_conn_info).into_boxed()
        } else {
            self.with_p2p_connection_info(priv_conn_info)
        }
    }

    /// Constructs private connection info with p2p info returned from `p2p` crate.
    /// p2p info is used for rendezvous connections - hole punching.
    fn with_p2p_connection_info(
        &self,
        mut priv_conn_info: PrivConnectionInfo,
    ) -> BoxFuture<PrivConnectionInfo, CrustError> {
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
            }).map_err(|(e, _stream)| e)
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
            PaAddr::Tcp(ref addr) => {
                p2p.add_tcp_addr_querier(PaTcpAddrQuerier::new(addr, peer.pub_key))
            }
            PaAddr::Utp(ref addr) => {
                p2p.add_udp_addr_querier(PaUdpAddrQuerier::new(addr, peer.pub_key))
            }
        }
    }
}

fn remove_rendezvous_servers(p2p: &P2p, addrs: &HashSet<PaAddr>) {
    for addr in addrs {
        match *addr {
            PaAddr::Tcp(addr) => p2p.remove_tcp_addr_querier(&addr),
            PaAddr::Utp(addr) => p2p.remove_udp_addr_querier(&addr),
        }
    }
}

fn make_bootstrap_cache(config: &ConfigFile) -> Result<BootstrapCache, CrustError> {
    let bootstrap_cache_name = config.read().bootstrap_cache_name.clone();
    let cache_file = bootstrap_cache_name.as_ref().map(|s| s.as_os_str());
    let bootstrap_cache =
        BootstrapCache::new(cache_file).map_err(CrustError::ReadBootstrapCache)?;
    bootstrap_cache.read_file();
    Ok(bootstrap_cache)
}

/// If configured, output Crust encryption keys to some file.
/// Then some external software can automatically pick those keys up and connect multiple Crust
/// peers using hard coded contacts.
fn try_write_encryption_keys(
    config: &ConfigFile,
    enc_keys: &PublicEncryptKey,
) -> Result<(), CrustError> {
    let keys_file = config.read().output_encryption_keys.clone();
    if let Some(fname) = keys_file {
        let file = File::create(fname.clone())?;
        serde_json::to_writer(file, enc_keys).unwrap();
        info!("Encryption keys written to '{:?}'", fname)
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_core::reactor::Core;

    mod set_rendezvous_servers {
        use super::*;
        use config::PeerInfo;

        #[test]
        fn it_sets_hard_coded_contacts_as_rendezvous_servers() {
            let mut core = unwrap!(Core::new());
            let handle = core.handle();

            let (listener0_pk, _listener0_sk) = gen_encrypt_keypair();
            let listener0 = unwrap!(TcpListener::bind(&addr!("0.0.0.0:0"), &handle));
            let listener0_info = PeerInfo::new(
                PaAddr::Tcp(unwrap!(listener0.local_addr()).unspecified_to_localhost()),
                listener0_pk,
            );

            let (listener1_pk, _listener1_sk) = gen_encrypt_keypair();
            let (_socket, listener1) = unwrap!(UtpSocket::bind(&addr!("0.0.0.0:0"), &handle));
            let listener1_info = PeerInfo::new(
                PaAddr::Utp(unwrap!(listener1.local_addr()).unspecified_to_localhost()),
                listener1_pk,
            );

            let config = unwrap!(ConfigFile::new_temporary());
            unwrap!(config.write()).hard_coded_contacts = vec![listener0_info, listener1_info];
            let p2p = P2p::default();

            set_rendezvous_servers(&p2p, &config);

            let query_tcp: BoxFuture<(), Void> = {
                let handle = handle.clone();
                p2p.tcp_addr_queriers()
                    .infallible()
                    .and_then(move |addr_querier| addr_querier.query(&addr!("0.0.0.0:0"), &handle))
                    .then(|res| match res {
                        Ok(x) => panic!("unexpected success: {:?}", x),
                        Err(_e) => Ok(()),
                    }).for_each(|()| Ok(()))
                    .into_boxed()
            };

            let query_udp: BoxFuture<(), Void> = {
                let handle = handle.clone();
                p2p.udp_addr_queriers()
                    .infallible()
                    .and_then(move |addr_querier| addr_querier.query(&addr!("0.0.0.0:0"), &handle))
                    .then(|res| match res {
                        Ok(x) => panic!("unexpected success: {:?}", x),
                        Err(_e) => Ok(()),
                    }).for_each(|()| Ok(()))
                    .into_boxed()
            };

            let l0 = {
                listener0
                    .incoming()
                    .with_timeout(Duration::from_secs(3), &handle)
                    .first_ok()
                    .map(|_stream| ())
                    .map_err(|e| panic!("didn't get a connection: {:?}", e))
            };
            let l1 = {
                listener1
                    .incoming()
                    .with_timeout(Duration::from_secs(3), &handle)
                    .first_ok()
                    .map(|_stream| ())
                    .map_err(|e| panic!("didn't get a connection: {:?}", e))
            };

            core.run(
                l0.join(l1)
                    .while_driving(query_tcp)
                    .map_err(|(v, _)| v)
                    .while_driving(query_udp)
                    .map_err(|(v, _)| v)
                    .map(|((((), ()), _query_tcp), _query_udp)| ()),
            ).void_unwrap()
        }
    }

    mod remove_rendezvous_servers {
        use super::*;

        #[test]
        fn it_removes_specified_rendezvous_servers_from_global_list() {
            let p2p = P2p::default();

            let (pk, _sk) = gen_encrypt_keypair();
            let addr_querier0 = PaTcpAddrQuerier::new(&addr!("1.2.3.4:4000"), pk);

            let (pk, _sk) = gen_encrypt_keypair();
            let addr_querier1 = PaUdpAddrQuerier::new(&addr!("1.2.3.5:5000"), pk);

            p2p.add_tcp_addr_querier(addr_querier0);
            p2p.add_udp_addr_querier(addr_querier1);

            let rm_servers: HashSet<PaAddr> =
                vec![tcp_addr!("1.2.3.4:4000"), utp_addr!("1.2.3.5:5000")]
                    .iter()
                    .cloned()
                    .collect();
            remove_rendezvous_servers(&p2p, &rm_servers);

            let mut core = unwrap!(Core::new());
            let handle = core.handle();
            let servers = core
                .run({
                    p2p.tcp_addr_queriers()
                        .with_readiness_timeout(Duration::from_secs(1), &handle)
                        .collect()
                }).void_unwrap();
            assert!(servers.is_empty());
            let servers = core
                .run({
                    p2p.udp_addr_queriers()
                        .with_readiness_timeout(Duration::from_secs(1), &handle)
                        .collect()
                }).void_unwrap();
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
}
