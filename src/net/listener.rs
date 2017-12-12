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

use priv_prelude::*;
use std::sync::{Arc, Mutex};

/// A handle for a single listening address. Drop this object to stop listening on this address.
pub struct Listener {
    _drop_tx: DropNotify,
    local_addr: PaAddr,
}

/// A set of listeners.
pub struct Listeners {
    handle: Handle,
    listeners_tx: UnboundedSender<(DropNotice, PaIncoming, HashSet<PaAddr>)>,
    addresses: Arc<Mutex<ObservableAddresses>>,
}

struct ObservableAddresses {
    current: HashSet<PaAddr>,
    observers: Vec<UnboundedSender<HashSet<PaAddr>>>,
}

impl ObservableAddresses {
    fn new() -> ObservableAddresses {
        ObservableAddresses {
            current: HashSet::new(),
            observers: Vec::new(),
        }
    }

    /// Adds given addresses to the addresses list.
    /// Also notifies the observers about the changes.
    fn add_and_notify<T>(&mut self, addrs: T)
    where
        T: IntoIterator<Item = PaAddr>,
    {
        let mut current = mem::replace(&mut self.current, HashSet::new());
        current.extend(addrs);
        self.observers.retain(|observer| {
            observer.unbounded_send(current.clone()).is_ok()
        });
        self.current = current;
    }
}

/// Created in tandem with a `Listeners`, represents the incoming stream of connections.
pub struct SocketIncoming {
    handle: Handle,
    listeners_rx: UnboundedReceiver<(DropNotice, PaIncoming, HashSet<PaAddr>)>,
    listeners: Vec<(DropNotice, PaIncoming, HashSet<PaAddr>)>,
    addresses: Arc<Mutex<ObservableAddresses>>,
}

impl Listeners {
    /// Create an (empty) set of listeners and a handle to its incoming stream of connections.
    pub fn new(handle: &Handle) -> (Listeners, SocketIncoming) {
        let (tx, rx) = mpsc::unbounded();
        let addresses = Arc::new(Mutex::new(ObservableAddresses::new()));
        let listeners = Listeners {
            handle: handle.clone(),
            listeners_tx: tx,
            addresses: Arc::clone(&addresses),
        };
        let incoming = SocketIncoming {
            handle: handle.clone(),
            listeners_rx: rx,
            listeners: Vec::new(),
            addresses: addresses,
        };
        (listeners, incoming)
    }

    /// All known addresses we may be contactable on. Includes global, NAT-mapped addresses.
    /// The channel can be used to be notified when the set of addresses changes.
    pub fn addresses(&self) -> (HashSet<PaAddr>, UnboundedReceiver<HashSet<PaAddr>>) {
        let (tx, rx) = mpsc::unbounded();
        let mut addresses = unwrap!(self.addresses.lock());
        addresses.observers.push(tx);
        (addresses.current.clone(), rx)
    }

    /// Adds a new listener to the set of listeners, listening on the given local address, and
    /// returns a handle to it.
    pub fn listener<UID: Uid>(&self, listen_addr: &PaAddr) -> IoFuture<Listener> {
        let handle = self.handle.clone();
        let tx = self.listeners_tx.clone();
        let addresses = Arc::clone(&self.addresses);
        let listen_addr = *listen_addr;

        // TODO(povilas): return future with our own error type instead of io::Error?
        PaListener::bind_public(&listen_addr, &handle)
            .map(|(listener, public_addr)| (listener, Some(public_addr)))
            .or_else(move |_| {
                PaListener::bind_reusable(&listen_addr, &handle).map(|listener| (listener, None))
            })
            .and_then(move |(listener, public_addr)| {
                let mut addrs = HashSet::new();
                addrs.extend(listener.expanded_local_addrs()?);
                addrs.extend(public_addr);

                let (drop_tx, drop_rx) = future_utils::drop_notify();

                let mut addresses = unwrap!(addresses.lock());
                addresses.add_and_notify(addrs.iter().cloned());

                let local_addr = unwrap!(listener.local_addr());
                let _ = tx.unbounded_send((drop_rx, listener.incoming(), addrs));

                Ok(Listener {
                    _drop_tx: drop_tx,
                    local_addr,
                })
            })
            .into_boxed()
    }
}

impl Stream for SocketIncoming {
    type Item = Socket<Void>;
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<Option<Socket<Void>>>> {
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
                    if let Async::Ready(Some((stream, addr))) = listener.poll()? {
                        let socket = Socket::wrap_pa(&self.handle, stream, addr);
                        return Ok(Async::Ready(Some(socket)));
                    }
                    i += 1;
                    continue;
                }
            }
            let (_, _, addrs) = self.listeners.swap_remove(i);
            let mut addresses = unwrap!(self.addresses.lock());
            let mut current = mem::replace(&mut addresses.current, HashSet::new());
            current.retain(|addr| !addrs.contains(addr));
            addresses.observers.retain(|observer| {
                observer.unbounded_send(current.clone()).is_ok()
            });
            addresses.current = current;
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
                addrs.current.insert(PaAddr::Tcp(addr!("1.2.3.4:1234")));

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
    }

    #[test]
    fn addresses_update() {
        let _logger = env_logger::init();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();

        let (listeners, socket_incoming) = Listeners::new(&handle);

        let future = {
            listeners
            .listener::<UniqueId>(&PaAddr::Tcp(addr!("0.0.0.0:0")))
            .map_err(|e| panic!(e))
            .and_then(move |listener0| {
                let addr0 = listener0.addr();
                let addrs0 = {
                    unwrap!(addr0.expand_local_unspecified())
                    .into_iter()
                    .collect::<HashSet<_>>()
                };
                let (addrs, addrs_rx) = listeners.addresses();
                assert!(addrs0.is_subset(&addrs));

                listeners
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
                    (addrs_rx, listeners, listener1, addrs0, addrs1)
                })
            })
            .and_then(|(addrs_rx, listeners, listener1, addrs0, addrs1)| {
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
                    drop(listeners);

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

        let (listeners, socket_incoming) = Listeners::new(&handle);

        let future = {
            listeners
                .listener::<UniqueId>(&PaAddr::Tcp(addr!("0.0.0.0:0")))
                .map_err(|e| panic!(e))
                .map(move |listener| {
                    mem::forget(listener);
                    listeners
                })
                .and_then(move |listeners| {
                    listeners
                        .listener::<UniqueId>(&PaAddr::Tcp(addr!("0.0.0.0:0")))
                        .map_err(|e| panic!(e))
                        .map(move |listener| {
                            mem::forget(listener);
                            listeners
                        })
                })
                .map(move |listeners| {
                    let (mut addrs, _) = listeners.addresses();
                    assert!(addrs.len() >= 2);

                    addrs.retain(|addr| !util::ip_addr_is_global(&addr.ip()));

                    let mut connectors = Vec::new();
                    for addr in &addrs {
                        let addr = *addr;
                        let handle0 = handle.clone();
                        let f = {
                            PaStream::direct_connect(&addr, &handle)
                                .map_err(|e| panic!(e))
                                .map(move |stream| {
                                    Socket::<PaAddr>::wrap_pa(&handle0, stream, addr)
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
                    .map(|()| drop(listeners))
                    };

                    handle.spawn(f);

                    addrs
                })
                .join({
                    socket_incoming
                        .map(|socket| {
                            socket
                                .change_message_type::<PaAddr>()
                                .into_future()
                                .map_err(|(e, _socket)| panic!(e))
                                .map(|(msg_opt, _socket)| unwrap!(msg_opt))
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
