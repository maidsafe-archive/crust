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

use future_utils::{self, DropNotice, DropNotify};
use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use net::protocol_agnostic::AcceptError;
use p2p::P2p;

use priv_prelude::*;
use std::sync::{Arc, Mutex};

/// A handle for a single listening address. Drop this object to stop listening on this address.
pub struct Listener {
    _drop_tx: DropNotify,
    local_addr: PaAddr,
}

/// Manages listeners that accept connections.
pub struct Acceptor {
    handle: Handle,
    listeners_tx: UnboundedSender<(DropNotice, PaIncoming, HashSet<PaAddr>)>,
    addresses: SharedObservableAddresses,
    p2p: P2p,
}

/// Holds a collection of addresses and notifies about changes.
/// Additionaly holds public addresses returned by `PaListener::bind_public()`.
struct ObservableAddresses {
    current: HashSet<PaAddr>,
    public: HashSet<PaAddr>,
    observers: Vec<UnboundedSender<HashSet<PaAddr>>>,
}

/// Addresses that can easily be shared across different futures.
type SharedObservableAddresses = Arc<Mutex<ObservableAddresses>>;

impl ObservableAddresses {
    fn new() -> ObservableAddresses {
        ObservableAddresses {
            current: HashSet::new(),
            public: HashSet::new(),
            observers: Vec::new(),
        }
    }

    /// Constructs `ObservableAddresses` that can be shared among futures.
    fn shared() -> SharedObservableAddresses {
        Arc::new(Mutex::new(Self::new()))
    }

    /// Adds given addresses to the addresses list.
    /// Also notifies the observers about the changes.
    fn add_and_notify<T>(&mut self, addrs: T)
    where
        T: IntoIterator<Item = PaAddr>,
    {
        self.modify_and_notify(|current_addrs| current_addrs.extend(addrs));
    }

    /// Removes all addresses (including public) that match with provided ones.
    fn remove_and_notify(&mut self, addrs: &HashSet<PaAddr>) {
        self.modify_and_notify(|current| current.retain(|addr| !addrs.contains(addr)));
        self.public.retain(|addr| !addrs.contains(addr));
    }

    /// Modifies current addresses and notifies observers about changes.
    fn modify_and_notify<F>(&mut self, modifier: F)
    where
        F: FnOnce(&mut HashSet<PaAddr>),
    {
        let mut current = mem::replace(&mut self.current, HashSet::new());
        modifier(&mut current);
        self.observers.retain(|observer| {
            observer.unbounded_send(current.clone()).is_ok()
        });
        self.current = current;
    }

    /// Adds public address to separate "public address" list.
    /// This list is used to determine whether listener is accessible publicly.
    fn add_public(&mut self, addr: PaAddr) {
        let _ = self.public.insert(addr);
    }
}

/// Created in tandem with a `Acceptor`, represents the incoming stream of connections.
pub struct SocketIncoming {
    listeners_rx: UnboundedReceiver<(DropNotice, PaIncoming, HashSet<PaAddr>)>,
    listeners: Vec<(DropNotice, PaIncoming, HashSet<PaAddr>)>,
    addresses: SharedObservableAddresses,
}

impl Acceptor {
    /// Create connection acceptor and a handle to its incoming stream of connections.
    pub fn new(handle: &Handle, p2p: P2p) -> (Acceptor, SocketIncoming) {
        let (tx, rx) = mpsc::unbounded();
        let addresses = ObservableAddresses::shared();
        let acceptor = Acceptor {
            handle: handle.clone(),
            listeners_tx: tx,
            addresses: Arc::clone(&addresses),
            p2p,
        };
        let incoming = SocketIncoming {
            listeners_rx: rx,
            listeners: Vec::new(),
            addresses: addresses,
        };
        (acceptor, incoming)
    }

    /// All known addresses we may be contactable on. Includes global, NAT-mapped addresses.
    /// The channel can be used to be notified when the set of addresses changes.
    pub fn addresses(&self) -> (HashSet<PaAddr>, UnboundedReceiver<HashSet<PaAddr>>) {
        let (tx, rx) = mpsc::unbounded();
        let mut addresses = unwrap!(self.addresses.lock());
        addresses.observers.push(tx);
        (addresses.current.clone(), rx)
    }

    /// Checks if any of the listeners has public address.
    pub fn has_public_addrs(&self) -> bool {
        let addrs = unwrap!(self.addresses.lock());
        !addrs.public.is_empty()
    }

    /// Adds a new listener to the set of listeners, listening on the given local address, and
    /// returns a handle to it.
    pub fn listener<UID: Uid>(&self, listen_addr: &PaAddr) -> IoFuture<Listener> {
        let handle = self.handle.clone();
        let tx = self.listeners_tx.clone();
        let addresses = Arc::clone(&self.addresses);
        let listen_addr = *listen_addr;

        PaListener::bind_public(&listen_addr, &handle, &self.p2p)
            .map(|(listener, public_addr)| (listener, Some(public_addr)))
            .or_else(move |_| {
                PaListener::bind_reusable(&listen_addr, &handle).map(|listener| (listener, None))
            })
            .and_then(move |(listener, public_addr)| {
                make_listener(listener, public_addr, addresses, tx)
            })
            .into_boxed()
    }
}

/// Constructs `Listener` from `PaListener`.
/// Uses `addresses` to notify `Acceptor` about new addresses `Crust` is listening on.
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn make_listener(
    listener: PaListener,
    public_addr: Option<PaAddr>,
    addresses: SharedObservableAddresses,
    listener_notifier: UnboundedSender<(DropNotice, PaIncoming, HashSet<PaAddr>)>,
) -> io::Result<Listener> {
    let mut addrs = HashSet::new();
    addrs.extend(listener.expanded_local_addrs()?);
    addrs.extend(public_addr);

    let (drop_tx, drop_rx) = future_utils::drop_notify();

    let mut addresses = unwrap!(addresses.lock());
    addresses.add_and_notify(addrs.iter().cloned());
    if let Some(addr) = public_addr {
        addresses.add_public(addr);
    }

    let local_addr = unwrap!(listener.local_addr());
    let _ = listener_notifier.unbounded_send((drop_rx, listener.incoming(), addrs));

    Ok(Listener {
        _drop_tx: drop_tx,
        local_addr,
    })
}

impl Stream for SocketIncoming {
    type Item = (PaStream, PaAddr);
    type Error = AcceptError;

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, AcceptError> {
        while let Async::Ready(incoming_opt) = unwrap!(self.listeners_rx.poll()) {
            let (drop_rx, incoming, addrs) = match incoming_opt {
                Some(x) => x,
                None => return Ok(Async::Ready(None)),
            };
            self.listeners.push((drop_rx, incoming, addrs));
        }

        let mut i = 0;
        while i < self.listeners.len() {
            {
                let &mut (ref mut drop_notice, ref mut listener, _) = &mut self.listeners[i];
                if let Ok(Async::NotReady) = drop_notice.poll() {
                    if let Async::Ready(Some(stream_with_addr)) = listener.poll()? {
                        return Ok(Async::Ready(Some(stream_with_addr)));
                    }
                    i += 1;
                    continue;
                }
            }
            let (_, _, addrs) = self.listeners.swap_remove(i);
            let mut addresses = unwrap!(self.addresses.lock());
            addresses.remove_and_notify(&addrs);
        }
        Ok(Async::NotReady)
    }
}

impl Listener {
    pub fn addr(&self) -> PaAddr {
        self.local_addr
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use env_logger;
    use hamcrest::prelude::*;
    use tokio_core::reactor::Core;
    use util::{self, UniqueId};

    mod observable_addresses {
        use super::*;
        mod add_and_notify {
            use super::*;

            #[test]
            fn it_adds_specified_addresses_to_the_list() {
                let mut addrs = ObservableAddresses::new();
                let _ = addrs.current.insert(PaAddr::Tcp(addr!("1.2.3.4:1234")));

                addrs.add_and_notify(vec![
                    PaAddr::Tcp(addr!("2.3.4.5:1234")),
                    PaAddr::Tcp(addr!("2.3.4.6:1234")),
                ]);

                let curr_addrs: Vec<PaAddr> = addrs.current.iter().cloned().collect();
                assert_that!(
                    &curr_addrs,
                    contains(vec![
                        PaAddr::Tcp(addr!("1.2.3.4:1234")),
                        PaAddr::Tcp(addr!("2.3.4.5:1234")),
                        PaAddr::Tcp(addr!("2.3.4.6:1234")),
                    ]).exactly()
                );
            }

            #[test]
            fn it_notifies_observers_about_address_changes() {
                let (tx, rx) = mpsc::unbounded();
                let mut addrs = ObservableAddresses::new();
                addrs.observers.push(tx);

                addrs.add_and_notify(vec![
                    PaAddr::Tcp(addr!("2.3.4.5:1234")),
                    PaAddr::Tcp(addr!("2.3.4.6:1234")),
                ]);

                let notified = unwrap!(rx.wait().map(|addrs| unwrap!(addrs)).nth(0))
                    .iter()
                    .cloned()
                    .collect::<Vec<PaAddr>>();
                assert_that!(
                    &notified,
                    contains(vec![
                        PaAddr::Tcp(addr!("2.3.4.5:1234")),
                        PaAddr::Tcp(addr!("2.3.4.6:1234")),
                    ]).exactly()
                );
            }
        }

        mod remove_and_notify {
            use super::*;

            #[test]
            fn it_does_nothing_when_given_addresses_are_not_in_our_list() {
                let mut addrs = ObservableAddresses::new();
                addrs.add_and_notify(vec![tcp_addr!("1.2.3.4:4000")]);

                addrs.remove_and_notify(&hashset!{tcp_addr!("1.2.3.5:5000")});

                assert!(addrs.current.contains(&tcp_addr!("1.2.3.4:4000")));
            }

            #[test]
            fn it_does_nothing_when_given_addresses_are_not_in_public_addr_list() {
                let mut addrs = ObservableAddresses::new();
                addrs.add_public(tcp_addr!("1.2.3.4:4000"));

                addrs.remove_and_notify(&hashset!{tcp_addr!("1.2.3.5:5000")});

                assert!(addrs.public.contains(&tcp_addr!("1.2.3.4:4000")));
            }

            #[test]
            fn it_removes_given_addresses() {
                let mut addrs = ObservableAddresses::new();
                addrs.add_and_notify(vec![tcp_addr!("1.2.3.4:4000"), tcp_addr!("1.2.3.5:5000")]);

                addrs.remove_and_notify(
                    &hashset!{tcp_addr!("1.2.3.5:5000"), tcp_addr!("1.2.3.6:6000")},
                );

                assert!(addrs.current.contains(&tcp_addr!("1.2.3.4:4000")));
                assert!(!addrs.current.contains(&tcp_addr!("1.2.3.5:5000")));
            }

            #[test]
            fn it_removes_given_addresses_from_public_addrs_list_too() {
                let mut addrs = ObservableAddresses::new();
                addrs.add_public(tcp_addr!("1.2.3.4:4000"));
                addrs.add_public(tcp_addr!("1.2.3.5:5000"));

                addrs.remove_and_notify(
                    &hashset!{tcp_addr!("1.2.3.5:5000"), tcp_addr!("1.2.3.6:6000")},
                );

                assert!(addrs.public.contains(&tcp_addr!("1.2.3.4:4000")));
                assert!(!addrs.public.contains(&tcp_addr!("1.2.3.5:5000")));
            }
        }

        mod add_public {
            use super::*;

            #[test]
            fn it_adds_public_address_to_designated_list() {
                let mut addrs = ObservableAddresses::new();

                addrs.add_public(utp_addr!("1.2.3.4:4000"));

                assert!(addrs.public.contains(&utp_addr!("1.2.3.4:4000")));
                assert_eq!(addrs.public.len(), 1);
            }
        }
    }

    mod acceptor {
        use super::*;

        mod has_public_addrs {
            use super::*;

            #[test]
            fn it_returns_true_when_theres_at_least_one_public_address() {
                let core = unwrap!(Core::new());
                let (acceptor, _) = Acceptor::new(&core.handle(), P2p::default());
                unwrap!(acceptor.addresses.lock()).add_public(utp_addr!("1.2.3.4:4000"));

                assert!(acceptor.has_public_addrs());
            }

            #[test]
            fn it_returns_false_when_none_of_listeners_have_public_address() {
                let core = unwrap!(Core::new());
                let (acceptor, _) = Acceptor::new(&core.handle(), P2p::default());

                assert!(!acceptor.has_public_addrs());
            }
        }
    }

    mod make_listener {
        use super::*;

        /// Helper to reduce boilerplate for addresses construction.
        fn observable_addresses<T>(addrs: T) -> SharedObservableAddresses
        where
            T: IntoIterator<Item = SocketAddr>,
        {
            let addresses = ObservableAddresses::shared();
            {
                let mut addreses = unwrap!(addresses.lock());
                addreses.add_and_notify(addrs.into_iter().map(PaAddr::Utp));
            }
            addresses
        }

        fn palistener(handle: &Handle) -> PaListener {
            let bind_addr = PaAddr::Utp(addr!("0.0.0.0:0"));
            unwrap!(PaListener::bind(&bind_addr, handle))
        }

        #[test]
        fn it_adds_listener_addresses_to_the_given_address_list() {
            let core = unwrap!(Core::new());
            let handle = core.handle();

            let (tx, _rx) = mpsc::unbounded();
            let addresses = observable_addresses(Vec::new());
            let listener = palistener(&handle);

            let public_addr = Some(utp_addr!("1.2.3.4:4000"));
            let _ = make_listener(listener, public_addr, Arc::clone(&addresses), tx);

            let addrs = unwrap!(addresses.lock());
            let public_addrs: Vec<PaAddr> = addrs.public.iter().cloned().collect();

            let expected_addrs = vec![utp_addr!("1.2.3.4:4000")];
            assert_that!(&public_addrs, contains(expected_addrs).exactly());
        }

        #[test]
        fn it_adds_public_listener_addresses_to_the_given_address_list_if_one_is_given() {
            let core = unwrap!(Core::new());
            let handle = core.handle();

            let (tx, _rx) = mpsc::unbounded();
            let addresses = observable_addresses(vec![addr!("1.2.3.4:4000")]);

            let listener = palistener(&handle);
            let mut expected_addrs = unwrap!(listener.expanded_local_addrs());
            expected_addrs.push(PaAddr::Utp(addr!("1.2.3.4:4000")));

            let _ = make_listener(listener, None, Arc::clone(&addresses), tx);

            let addrs = unwrap!(addresses.lock());
            let addrs: Vec<PaAddr> = addrs.current.iter().cloned().collect();

            assert_that!(&addrs, contains(expected_addrs).exactly());
        }

        #[test]
        fn it_notifies_about_new_listener() {
            let mut core = unwrap!(Core::new());
            let handle = core.handle();

            let (tx, rx) = mpsc::unbounded();
            let addresses = ObservableAddresses::shared();

            let listener = palistener(&handle);
            let local_addrs = unwrap!(listener.expanded_local_addrs());

            let _ = make_listener(listener, None, Arc::clone(&addresses), tx);

            let (_, _, actual_addrs) = unwrap!(
                core.run(
                    rx.into_future()
                        .and_then(|(listener_info, _rx)| Ok(unwrap!(listener_info)))
                        .map_err(|_| panic!("Failed to receive listener info.")),
                )
            );

            let actual_addrs: Vec<PaAddr> = actual_addrs.iter().cloned().collect();
            assert_that!(&actual_addrs, contains(local_addrs).exactly());
        }
    }

    #[test]
    fn addresses_update() {
        let _logger = env_logger::init();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();

        let (acceptor, socket_incoming) = Acceptor::new(&handle, P2p::default());

        let future = {
            acceptor
            .listener::<UniqueId>(&PaAddr::Tcp(addr!("0.0.0.0:0")))
            .map_err(|e| panic!(e))
            .and_then(move |listener0| {
                let addr0 = listener0.addr();
                let addrs0 = {
                    unwrap!(addr0.expand_local_unspecified())
                    .into_iter()
                    .collect::<HashSet<_>>()
                };
                let (addrs, addrs_rx) = acceptor.addresses();
                assert!(addrs0.is_subset(&addrs));

                acceptor
                .listener::<UniqueId>(&PaAddr::Tcp(addr!("0.0.0.0:0")))
                .map_err(|e| panic!(e))
                .map(move |listener1| {
                    let addr1 = listener1.addr();
                    let addrs1 = {
                        unwrap!(addr1.expand_local_unspecified())
                        .into_iter()
                        .collect::<HashSet<_>>()
                    };
                    drop(listener0);
                    (addrs_rx, acceptor, listener1, addrs0, addrs1)
                })
            })
            .and_then(|(addrs_rx, acceptor, listener1, addrs0, addrs1)| {
                drop(listener1);

                let addrs0_c0 = addrs0.clone();
                let addrs0_c1 = addrs0.clone();
                let addrs0_c2 = addrs0.clone();
                let addrs1_c0 = addrs1.clone();
                let addrs1_c1 = addrs1.clone();
                let addrs1_c2 = addrs1.clone();

                addrs_rx
                .into_future()
                .and_then(move |(addrs_opt, addrs_rx)| {
                    let addrs = unwrap!(addrs_opt);
                    assert!(addrs0_c0.is_subset(&addrs));
                    assert!(addrs1_c0.is_subset(&addrs));

                    addrs_rx
                    .into_future()
                })
                .and_then(move |(addrs_opt, addrs_rx)| {
                    let addrs = unwrap!(addrs_opt);
                    assert!(!addrs0_c1.is_subset(&addrs));
                    assert!(addrs1_c1.is_subset(&addrs));

                    addrs_rx
                    .into_future()
                })
                .and_then(move |(addrs_opt, addrs_rx)| {
                    let addrs = unwrap!(addrs_opt);
                    assert!(!addrs0_c2.is_subset(&addrs));
                    assert!(!addrs1_c2.is_subset(&addrs));
                    drop(acceptor);

                    addrs_rx
                    .into_future()
                })
                .map(|(addrs_opt, _addrs_rx)| {
                    assert_eq!(addrs_opt, None)
                })
                .map_err(|_e| {
                    unreachable!()
                })
            })
            .join({
                socket_incoming
                .map_err(|e| panic!("incoming error: {}", e))
                .for_each(|_socket| -> io::Result<()> {
                    panic!("unexpected connection");
                })
            })
            .map(|((), ())| ())
        };
        let res = core.run(future);
        unwrap!(res)
    }

    #[test]
    fn incoming_sockets() {
        let _logger = env_logger::init();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();
        let handle0 = handle.clone();

        let (acceptor, socket_incoming) = Acceptor::new(&handle, P2p::default());

        let config = unwrap!(ConfigFile::new_temporary());
        let future = {
            acceptor
                .listener::<UniqueId>(&PaAddr::Tcp(addr!("0.0.0.0:0")))
                .map_err(|e| panic!(e))
                .map(move |listener| {
                    mem::forget(listener);
                    acceptor
                })
                .and_then(move |acceptor| {
                    acceptor
                        .listener::<UniqueId>(&PaAddr::Tcp(addr!("0.0.0.0:0")))
                        .map_err(|e| panic!(e))
                        .map(move |listener| {
                            mem::forget(listener);
                            acceptor
                        })
                })
                .map(move |acceptor| {
                    let (mut addrs, _) = acceptor.addresses();
                    assert!(addrs.len() >= 2);

                    addrs.retain(|addr| !util::ip_addr_is_global(&addr.ip()));

                    let mut connectors = Vec::new();
                    for addr in &addrs {
                        let addr = *addr;
                        let handle0 = handle.clone();
                        let f = {
                            PaStream::direct_connect(&addr, &handle, &config)
                                .map_err(|e| panic!(e))
                                .map(move |stream| {
                                    Socket::<PaAddr>::wrap_pa(
                                        &handle0,
                                        stream,
                                        addr,
                                        CryptoContext::null(),
                                    )
                                })
                                .and_then(move |socket| socket.send((0, addr)))
                                .map(|_socket| ())
                                .map_err(|e| panic!(e))
                        };
                        connectors.push(f);
                    }

                    let f = {
                        let handle = handle.clone();
                        future::join_all(connectors)
                    .and_then(move |_| Timeout::new(Duration::from_secs(1), &handle))
                    .map_err(|e| panic!(e))
                    .map(|()| drop(acceptor))
                    };

                    handle.spawn(f);

                    addrs
                })
                .join({
                    socket_incoming
                        .map(move |(stream, addr)| {
                            let socket = Socket::<PaAddr>::wrap_pa(
                                &handle0,
                                stream,
                                addr,
                                CryptoContext::null(),
                            );
                            socket
                                .change_message_type::<PaAddr>()
                                .into_future()
                                .map_err(|(e, _stream_with_addr)| panic!(e))
                                .map(|(msg_opt, _stream_with_addr)| unwrap!(msg_opt))
                        })
                        .buffer_unordered(64)
                        .collect()
                        .map(|v| v.into_iter().collect::<HashSet<_>>())
                        .into_boxed()
                })
                .map(|(addrs0, addrs1)| {
                    assert_eq!(addrs0, addrs1);
                })
        };
        let res = core.run(future);
        unwrap!(res)
    }
}
