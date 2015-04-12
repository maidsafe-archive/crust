# crust
Reliable p2p network connections in Rust with NAT traversal. One of the most needed libraries for any server-less / decentralised project.

|Travis| Drone.io|Appveyor|Coverage|
|:------:|:-------:|:-------:|:------:|
|[![Build Status](https://travis-ci.org/dirvine/crust.svg?branch=master)](https://travis-ci.org/dirvine/crust)|[![Build Status](https://drone.io/github.com/dirvine/crust/status.png)](https://drone.io/github.com/dirvine/crust/latest)|[![Build status](https://ci.appveyor.com/api/projects/status/7bl67hscnfljxxt3?svg=true)](https://ci.appveyor.com/project/dirvine/crust)|[![Coverage Status](https://coveralls.io/repos/dirvine/crust/badge.svg)](https://coveralls.io/r/dirvine/crust)|


[API Documentation](http://dirvine.github.io/crust/crust/)

#Overview

This library will allow p2p networks to establish and maintain a number of connections in a group when informed by users of the library. As connections are made these are passed up and the user can select which connections to maintain or drop. The library has a bootstrap handler which will attempt to reconnect to any previous "**direct connected**" nodes.

Tcp conections are always favoured as these wll be by default direct connected (until we can test and confirm tcp hole punching). Tcp is also a known reliable protocol. Reliable udp is the fallback protocol and very effective.

The library contains a beackon system for finding nodes on a local network, this will be extended using a gossip type protocol for multi hop discovery. 

Encryption of all streams will also allow for better masking of such networks and add to security, this is done also considering the possibility of attack where adversaries can send data continually we must decrypt prior to handling (meaning we do the work). There are several methods to mitigate this, including alerting upper layers of such activity. The user of the library has the option to provide a blacklisting capapbility per session to disconnect such nodes 'en masse'.

_direct connected == Nodes we were previously connected to. tcp nodes or reliable udp nodes that allow incoming connections (i.e. direct or full cone nat that has been hole punched). This library also supports fallback endpoints being passed at construction that will allow a fallback should none of the nodes form any previous session are available._  

##Nat traversal/Handling 

Several methods are used for NAT traversal, UpNP, hole punching [See here for tcp NAT traversal] (http://www.cmlab.csie.ntu.edu.tw/~franklai/NATBT.pdf) [and here for ucp/dht NAT traversal
  ](http://maidsafe.net/Whitepapers/pdf/DHTbasedNATTraversal.pdf) etc. These methods will be added to by the community to allow a p2p network that cannto be easily blocked. By default this library spawns sockets randomly, meaning ndoes appear on several ports over time and very difficult to trace.  


##Todo Items
- [ ] Tcp Networking
  - [x] Tcp live port and backup random port selection 
  - [x] Create send/rcv channel from routing to connections object
  - [x] Implement test for basic "hello world" two way communication
  - [x] Set up Udp broadcast and respond when we have a port (we listen on any random port above 1024 [user space port])  available (broadcast port is 5483)
  - [ ] Have connection manger start, broadcast on udp broadcast for port 5483 (later multicast for ipv6)
  - [ ] Link ability to read and write bootstrap file as well as send to any node requesting it. 
  - [ ] Add connection established/lost messages to be passed to routing (via channel)
  - [ ] Add maintain_connection() to connecton manager for lib.rs to be able to confirm a routing table contact we must keep. 
  - [ ] Benchmark tx/rv number of packets 
  - [ ] Benchmark tx/rc Bytes per second
- [ ] Allow tcp and then utp connections and wrap in connection object. [See here for tcp NAT traversal] (http://www.cmlab.csie.ntu.edu.tw/~franklai/NATBT.pdf) [and here for ucp/dht NAT traversal
  ](http://maidsafe.net/Whitepapers/pdf/DHTbasedNATTraversal.pdf)
- [ ] Version 0.0.8
- [ ] Utp Networking
  - [ ] Utp live port and backup random port selection 
  - [ ] Create send/rcv channel from routing to connections object
  - [ ] Implement test for basic "hello world" two way communication
  - [ ] Add connection established/lost messages to be passed to routing (via channel)
  - [ ] Benchmark tx/rv number of packets 
  - [ ] Benchmark tx/rc Bytes per second 
- [ ] Version 0.1 (crates.io)
