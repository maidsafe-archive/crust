# Crust
Reliable p2p network connections in Rust with NAT traversal. One of the most needed libraries for any server-less, decentralised project.

|Crate|Travis|Windows|OSX|Coverage|
|:------:|:-------:|:------:|:------:|:------:|
|[![](http://meritbadge.herokuapp.com/crust)](https://crates.io/crates/crust)|[![Build Status](https://travis-ci.org/maidsafe/crust.svg?branch=master)](https://travis-ci.org/maidsafe/crust)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=crust_win64_status_badge)](http://ci.maidsafe.net:8080/job/crust_win64_status_badge/)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=crust_osx_status_badge)](http://ci.maidsafe.net:8080/job/crust_osx_status_badge/)|[![Coverage Status](https://coveralls.io/repos/maidsafe/crust/badge.svg)](https://coveralls.io/r/maidsafe/crust)|


| [API Documentation](http://maidsafe.github.io/crust/crust/) | [MaidSafe System Documention](http://systemdocs.maidsafe.net/) | [MaidSafe web site](http://www.maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |

#Overview

![crusty] (https://github.com/dirvine/crust/blob/master/img/crust-diagram_1024.png?raw=true)

This library will allow p2p networks to establish and maintain a number of connections in a group when informed by users of the library. As connections are made they are passed up and the user can select which connections to maintain or drop. The library has a bootstrap handler which will attempt to reconnect to any previous "**direct connected**" nodes.

TCP connections are always favoured as these will be by default direct connected (until tcp hole punching can be tested). TCP is also a known reliable protocol. Reliable UDP is the fallback protocol and very effective.

The library contains a beacon system for finding nodes on a local network, this will be extended using a gossip type protocol for multi hop discovery.

Encryption of all streams will also allow for better masking of such networks and add to security, this is done also considering the possibility of attack where adversaries can send data continually we must decrypt prior to handling (meaning we do the work). There are several methods to mitigate this, including alerting upper layers of such activity. The user of the library has the option to provide a blacklisting capability per session to disconnect such nodes 'en masse'.

_direct connected == Nodes we were previously connected to. TCP nodes or reliable UDP nodes that allow incoming connections (i.e. direct or full cone nat that has been hole punched). This library also supports fallback endpoints being passed at construction that will allow a fallback should nodes from previous sessions become unavailable.

##Nat traversal/Handling

Several methods are used for NAT traversal, UpNP, hole punching [See here for TCP NAT traversal] (http://www.cmlab.csie.ntu.edu.tw/~franklai/NATBT.pdf) and [here for UCP/DHT NAT traversal
  ](http://maidsafe.net/Whitepapers/pdf/DHTbasedNATTraversal.pdf) etc. These methods will be added to by the community to allow a p2p network that cannot be easily blocked. By default this library spawns sockets randomly, enabling nodes to appear on several ports over time. This makes them very difficult to trace.


##Todo Items
- [ ] Tcp Networking
  - [x] Tcp live port and backup random port selection
  - [x] Create send/rcv channel from routing to connections object
  - [x] Implement test for basic "hello world" two way communication
  - [x] Set up Udp broadcast and respond when we have a port (we listen on any random port above 1024 [user space port])  available (broadcast port is 5483)
  - [x] Add connection established/lost/ new messages to be passed to routing (via channel)
  - [x] Implement connect() in connection manager
  - [x] Allow tcp and then utp connections option and wrap in connection object.
  ](http://maidsafe.net/Whitepapers/pdf/DHTbasedNATTraversal.pdf)
- [x] Update handle connect for TCP
- [x] Remove FailedToConnect event
- [x] Integrate bootstrap (Link ability to read and write bootstrap file)
- [x] Integrate beacon (Have connection manger start, broadcast on udp broadcast for port 5483 (later multicast for ipv6)
- [x] Send serialised bootstrap info as part of beacon reply (Link ability to send bootstrap file to any node requesting it)
- [ ] Examples:
  - [x] Broadcaster
  - [x] Broadcast receiver
  - [x] CLI Example - options:
    - [x] Join / Start a node(optionally provide bootstrap info)
    - [x] Allow sending messages at various rates per second
    - [x] Print Incomming message rate per second
  - [x] Local Network Test. 12 Linux, 2 OSX, 2 WIN
  - [ ] 101 Droplet test
- [ ] Version 0.0.8
- [ ] Have ConnectionManager guarantee at most one connection between any two nodes
- [ ] Utp Networking
  - [ ] Utp live port and backup random port selection
  - [ ] Create send/rcv channel from routing to connections object
  - [ ] Implement test for basic "hello world" two way communication
  - [ ] Add connection established/lost messages to be passed to routing (via channel)
  - [ ] Benchmark tx/rv number of packets
  - [ ] Benchmark tx/rc Bytes per second
  - [ ] NAT traversal  [See here for tcp NAT traversal] (http://www.cmlab.csie.ntu.edu.tw/~franklai/NATBT.pdf)
- [ ] Benchmark tx/rv number of packets
- [ ] Benchmark tx/rc Bytes per second
- [ ] Implement `get_endoints() -> Vec<EndPointPair>` where `EndpointPair` is struct with `Option<ExternalEndpoint>` and has a Proto identifier field
  - [ ] Implement UpNp
  - [ ] Implement NAT hole punch (udp) for reliable udp
- [ ] Version 0.1 (crates.io)
- [ ] Tcp hole punching as per paper
- [ ] Tracer tcp (TCP with magic in clear [unencrypted])
- [ ] Wireshark module for tracer TCP
