# crust
Reliable p2p network connections in Rust with NAT traversal. One of the most needed libraries for any server-less / decentralised project.

|Travis| Drone.io|Appveyor|Coverage|
|:------:|:-------:|:-------:|:------:|
|[![Build Status](https://travis-ci.org/dirvine/crust.svg?branch=master)](https://travis-ci.org/dirvine/crust)|[![Build Status](https://drone.io/github.com/dirvine/crust/status.png)](https://drone.io/github.com/dirvine/crust/latest)|[![Build status](https://ci.appveyor.com/api/projects/status/7bl67hscnfljxxt3?svg=true)](https://ci.appveyor.com/project/dirvine/crust)|[![Coverage Status](https://coveralls.io/repos/dirvine/crust/badge.svg)](https://coveralls.io/r/dirvine/crust)|


[Documentation](http://dirvine.github.io/crust/crust/)

##Todo Items
- [ ] Tcp Networking
  - [x] Tcp live port and backup random port selection 
  - [x] Create send/rcv channel from routing to connections object
  - [x] Implement test for basic "hello world" two way communication
  - [x] Set up Udp broadcast and respond when we have live port available (5483)
  - [ ] Have connection manger start, broadcast on udp broadcast for port 5483 (later multicast for ipv6)
  - [ ] Link ability to read and write bootstrap file as well as send to any node requesting it. 
  - [ ] Add connection established/lost messages to be passed to routing (via channel)
  - [ ] Add maintain_connection() to connecton manager for lib.rs to be able to confirm a routing table contact we must keep. 
  - [ ] Benchmark tx/rv number of packets 
  - [ ] Benchmark tx/rc Bytes per second
- [ ] Allow tcp and then utp connections and wrap in connection object. [See here for tcp NAT traversal] (http://www.cmlab.csie.ntu.edu.tw/~franklai/NATBT.pdf) [and here fur ucp/dht NAT traversal
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
