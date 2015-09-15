# CRUST - Change Log

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
