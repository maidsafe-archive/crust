# Crust

**Maintainer:** Spandan Sharma (spandan.sharma@maidsafe.net)

Reliable p2p network connections in Rust with NAT traversal. One of the most needed libraries for any server-less, decentralised project.

|Crate|Documentation|Linux/OS X|Windows|Issues|
|:---:|:-----------:|:--------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/crust)](https://crates.io/crates/crust)|[![Documentation](https://docs.rs/crust/badge.svg)](https://docs.rs/crust)|[![Build Status](https://travis-ci.org/maidsafe/crust.svg?branch=master)](https://travis-ci.org/maidsafe/crust)|[![Build status](https://ci.appveyor.com/api/projects/status/ajw6ab26p86jdac4/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/crust/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/crust.png?label=ready&title=Ready)](https://waffle.io/maidsafe/crust)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Overview

![crusty](https://github.com/maidsafe/crust/blob/master/img/crust-diagram_1024.png?raw=true)

This library will allow p2p networks to establish and maintain a number of connections in a group when informed by users of the library. As connections are made they are passed up and the user can select which connections to maintain or drop. The library has a bootstrap handler which will attempt to reconnect to any previous "**direct connected**" nodes.

TCP connections are always favoured as these will be by default direct connected (until TCP hole punching can be tested). TCP is also a known reliable protocol. Reliable UDP is the fallback protocol and very effective.

The library contains a beacon system for finding nodes on a local network, this will be extended using a gossip type protocol for multi hop discovery.

Encryption of all streams will also allow for better masking of such networks and add to security, this is done also considering the possibility of attack where adversaries can send data continually we must decrypt prior to handling (meaning we do the work). There are several methods to mitigate this, including alerting upper layers of such activity. The user of the library has the option to provide a blacklisting capability per session to disconnect such nodes 'en masse'.

_direct connected_ == Nodes we were previously connected to. TCP nodes or reliable UDP nodes that allow incoming connections (i.e. direct or full cone nat that has been hole punched). This library also supports fallback endpoints being passed at construction that will allow a fallback should nodes from previous sessions become unavailable.

## NAT Traversal/Handling

Several methods are used for NAT traversal such as UpNP and hole punching. [See here for TCP NAT traversal](http://www.goto.info.waseda.ac.jp/~wei/file/wei-apan-v10.pdf) and [here for UCP/DHT NAT traversal
  ](http://docs.maidsafe.net/Whitepapers/pdf/DHTbasedNATTraversal.pdf) etc. These methods will be added to by the community to allow a p2p network that cannot be easily blocked. By default this library spawns sockets randomly, enabling nodes to appear on several ports over time. This makes them very difficult to trace.

## License

Licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).
