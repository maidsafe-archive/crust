# CRUST - Change Log

## [0.15.0]
- Integrate with mio
   - This currently uses a temporary mio fork (`tmp_mio`) [with windows bug fix](https://github.com/carllerche/mio/pull/401).
   - Redesign with State Pattern.
- Bring number of persistent threads in crust to 1.
   - Previously we would have multiple threads _per connection_ leading to huge number of context switches which was inefficient. It was not uncommon to see more than 200 threads for a little over 60 connections (Routing Table size > 60).
   - Now in many of our tests where cpu would constantly hover around 100%, we have cpu now calm at around 1-5% and peaks to 30% temporarily only during peak stress (Lot of churn and data exchange).
- Make all system calls async.
   - Switch from application level concurrency primitives to operating system level concurrency.
   - Now with event based mechanism, when kernel is not ready for some state we steal that opportunity to have it service some other state it is ready for which keeps the event pipeline hot and optimal.
- Attempt bootstrapping in parallel.
   - This increases the speed of bootstrap process. Previously the sequential bootstrap meant we went to next potential peer only if the currently attempted one failed.
- Remove some of the 1st party dependant crates and move it in as modules.
- Cleaned out crust config file removing deprecated options.
- Integrate stun service into connection listeners instead of having them as separate peers.
- Crust API updates to rename OurConnectionInfo, TheirConnectionInfo to PrivConnectionInfo and PubConnectionInfo.
- Support bootstrap blacklist.

## [0.14.0]
- Depend on maidsafe_utilities 0.6.0.
- Fix endianness issue.

## [0.13.2]
- Tweak the algorithm for dropping messages when the bandwitdh is insufficient.

## [0.13.1]
- Ensure dropped duplicate connections dont have messages in transit

## [0.13.0]
- Add message priority to send high-priority messages first and if bandwidth is
  insufficient, drop the low-priority ones.
- Add the `network_name` option to prevent unwanted connections and facilitate
  starting separate test networks.
- Avoid duplicate connections to the same peer.

## [0.12.0]
- Remove uTP support.
- Implement heartbeat messages to detect lost connections more quickly.
- Add a version number to the protocol to avoid connecting to incompatible
  peers.
- Re-implement TCP send/receive using payload size + data.

## [0.11.1]
- Make deserialisation errors as debug instead of error.

## [0.11.0]
- Minor cleanup.
- Removed unneeded dependency.
- Tests fixed.

## [0.10.0]
- Peer connections wait for both sides before sending `NewPeer` events.
- Enable uTP (still buggy).
- Add TCP rendezvous.
- Support port forwarding with ports specified as TCP acceptors.
- Never raise `NewPeer` and `LostPeer` events for ourselves.
- Update config file format to include service discovery port bootstrap cache
  name.
- Fix duplicate `NewPeer` events.
- Fix issues 619, 606, 605, 601, 589 and 595.

## [0.9.0]
- Remove cbor and ip dependencies.
- Expose the PeerId in TheirConnectionInfo.

## [0.8.5]
- Implement Rand for PeerId.

## [0.8.4]
- Update dependencies

## [0.8.3]
- Bugfixes
- Disable uTP

## [0.8.2]
- Randomise the bootstrap contact order.

## [0.8.1]
- Restrict to TCP only until the UTP problems are fixed.
- Add peer IDs, and identify connections with them instead of `Connection`
  objects.

## [0.8.0]
- Removes feature gates, Crust can now compile on stable rust compiler.

## [0.7.0]
- OnConnect, OnAccept and OnRendezvousConnect events now report what the remote
  peer sees this peer's endpoint as

## [0.6.1]
- Replaced Event with EventSender from maidsafe_utilities

## [0.6.0]
- Change API to notify failures (e.g. now it is
  `OnConnect(io::Result<Connection>, u32 /* token */)`.
- Don't start any acceptor implicitly.
- Remove default acceptors settings from config file.
- Use memory mapped file abstractions to manage bootstrap cache files. We no
  longer rely on a "file cache owner" that is chosen based on whoever is
  successful to start some default acceptor implicitly.
- A bugfix to uTP code.
- Lint changes.
- A new benchmark.

## [0.5.1]
- Remove wildcards from dependencies.

## [0.5.0]
- Update lint checks
- Style changes
- Documentation updates
- Hole punching API
  - Functions to use the P2P network to help punch an UDP hole
  - Rendezvous connections using custom UDP sockets
- Breakages in network protocol (handshake strucutre changed)
- Updated examples
- New example: reporter
- Bug fixes
- API updates (now an `u32` token is associated with connections)
- Remove dependency on packages that were unnecessary and were
  causing stability issues on crust
- Tests are more predictable.
- Tests are more stable (tests can contain bugs too).
- Changes to build against most recent Rust (and libraries).

## [0.4.2]
- Adapts to new rust-utp API

## [0.4.1]
- Fixes
- `service::test::network` test is working again

## [0.4.0]
- Small change in protocol as preparation for UDP hole punching
- Impl of Ord for transport::Endpoint no longer panics
- Exports util function `ifaddrs_if_unspecified`
- Calls which start accepting connections now return real socket addresses where
  IP is usually 0.0.0.0 (to be used with the fn from previous bullet)

## [0.3.2]
- Fixes explicit panic when trying to send on a closed connection

## [0.3.1]
- Reduces number of threads by using channels.
- Renames ConnectionManager to Service
- All Service public API functions are now async
- Removes NewConnection and NewBootstrapConnection events in favor of OnConnect and OnAccept
- Code reduction by doing encoding and decoding at one place (helped fixing a decoder bug we had)
- Consistent usage of the 5483 and 5484 ports

## [0.3.0]
- Revert-revert ConnectionManager::new API change

## [0.2.10]
- Revert ConnectionManager::new API change

## [0.2.9]
- ConnectionManager starts accepting connections as soon as constructed now
- Config file now also specifies optional TCP and UTP listening ports
- Improved documentation
- Fixed [#288](https://github.com/maidsafe/crust/issues/288) unsafe multithreaded access to the bootstrap file.

## [0.2.8]
- Updated sample config file
- Updated crust_peer example to use config file
- Changed config- and bootstrap-file-handling to terminate application if file is unreadable
- Fixed bug causing infinite bootstrap loop in Routing

## [0.2.7]
- Refactored config- and bootstrap-file-handling

## [0.2.6]
- [MAID-1142](https://maidsafe.atlassian.net/browse/MAID-1142) Add UTP protocol support to crust
- [#259](https://github.com/maidsafe/crust/issues/259) Build failure on Win32
- Added AppVeyor script

## [0.2.5]
- [#221](https://github.com/maidsafe/crust/issues/221) getting more bootstrap connections than expected

## [0.2.4]
- [#215](https://github.com/maidsafe/crust/issues/215) `connection_manager::get_own_endpoints()` should not return loopback address

## [0.2.3]
- [#230](https://github.com/maidsafe/crust/issues/230) Cannot compile crust - crust_peer - #[forbid(unused_mut)]

## [0.2.2]
- [#223](https://github.com/maidsafe/crust/issues/223) Error: use of unstable library feature 'udp_extras': available through the `net2` crate on crates.io

## [0.2.1]
- [#207](https://github.com/maidsafe/crust/issues/207) `ConnectionManager::get_own_endpoints` returns 0 as port

##### RUST-3 Sprint tasks
- [MAID-1149](https://maidsafe.atlassian.net/browse/MAID-1149) Split bootstrap cache file in two files (config & cache)
- [MAID-1136](https://maidsafe.atlassian.net/browse/MAID-1136) Add a new event NewBootstrapConnection and make bootstrap method non blocking.
- [MAID-1146](https://maidsafe.atlassian.net/browse/MAID-1146) Attempt Bootstrap continuously until it succeeds
- [MAID-1148](https://maidsafe.atlassian.net/browse/MAID-1148) Update bootstrap handler to maintain recent endpoints
- [MAID-1161](https://maidsafe.atlassian.net/browse/MAID-1161) Update start_listening() to take no parameters
- [MAID-1162](https://maidsafe.atlassian.net/browse/MAID-1162) Add get_beacon_acceptor_port() method only for tests
- [MAID-1264](https://maidsafe.atlassian.net/browse/MAID-1264) Update API to hide configuration file path

## [0.2.0]
- [MAID-1132](https://maidsafe.atlassian.net/browse/MAID-1132) Integrate UPnP
- [MAID-1139](https://maidsafe.atlassian.net/browse/MAID-1139) Remove Crust API’s start_listening2() and expose `get_own_endpoints()`

## [0.1.5]
- Updated dependency's version

## [0.1.4]
- Made ConnectionManager::seek_peers() private

## [0.1.3]
- Travis document generation build script updated

## [0.1.2]
- Fixed documentation links

## [0.1.1]
- Removed sodiumoxide dependency

## [0.1.0]

## [0.0.66]
- [#140](https://github.com/maidsafe/crust/issues/140) Bootstrap file format

## [0.0.65]
- [#148](https://github.com/maidsafe/crust/issues/148) Ensure contents of Bootstrap file are unique Fixes
- [#151](https://github.com/maidsafe/crust/issues/151) fix build failures with rust nightly

## [0.0.64]
- Code clean up

## [0.0.63]
- [#134](https://github.com/maidsafe/crust/issues/134) First node doesn't read its own bootstrap list

## [0.0.62]
- [MAID-1125](https://maidsafe.atlassian.net/browse/MAID-1125) Update Bootstrap Handler to use Json format.

## [0.0.61]
- [MAID-1124](https://maidsafe.atlassian.net/browse/MAID-1124) Get a list of public IPs for others to connect to

## [0.0.60]
- [MAID-1075](https://maidsafe.atlassian.net/browse/MAID-1075) Correct bug; listening on local port (127.0.0.1)
- [MAID-1122](https://maidsafe.atlassian.net/browse/MAID-1122) Windows ifaddr resolution

## [0.0.1 - 0.0.8]
- Remove FailedToConnect Event
- Update process for Connecting in TCP
- Tcp Networking
  -  Tcp live port and backup random port selection
  -  Create send/rcv channel from routing to connections object
  -  Implement test for basic "hello world" two way communication
  -  Set up Udp broadcast and respond when we have a port (we listen on any random port above 1024 [user space port])  available (broadcast port is 5484)
  -  Add connection established/lost/ new messages to be passed to routing (via channel)
  -  Implement connect() in connection manager
  -  Allow tcp and then utp connections option and wrap in connection object.
  ](http://maidsafe.net/Whitepapers/pdf/DHTbasedNATTraversal.pdf)
-  Update handle connect for TCP
-  Remove FailedToConnect event
-  Integrate bootstrap (Link ability to read and write bootstrap file)
-  Integrate beacon (Have connection manger start, broadcast on udp broadcast for port 5484 (later multicast for ipv6)
-  Send serialised bootstrap info as part of beacon reply (Link ability to send bootstrap file to any node requesting it)
- Examples:
  -  Broadcaster
  -  Broadcast receiver
  -  CLI Example - options:
    -  Join / Start a node(optionally provide bootstrap info)
    -  Allow sending messages at various rates per second
    -  Print Incomming message rate per second
  -  Local Network Test. 12 Linux, 2 OSX, 2 WIN
  - 101 Droplet test
- Version 0.0.8
