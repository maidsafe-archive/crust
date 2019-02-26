# Crust

Reliable p2p network connections in Rust with NAT traversal. One of the most needed libraries for any server-less, decentralised project.

|Crate|Documentation|Linux/macOS|Windows|Issues|
|:---:|:-----------:|:--------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/crust)](https://crates.io/crates/crust)|[![Documentation](https://docs.rs/crust/badge.svg)](https://docs.rs/crust)|[![Build Status](https://travis-ci.com/maidsafe/crust.svg?branch=master)](https://travis-ci.com/maidsafe/crust)|[![Build status](https://ci.appveyor.com/api/projects/status/ajw6ab26p86jdac4/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/crust/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/crust.png?label=ready&title=Ready)](https://waffle.io/maidsafe/crust)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

<a name="overview"></a>
## Overview

![crusty](https://github.com/maidsafe/crust/blob/master/img/crust-diagram_1024.png?raw=true)

Crust is a low level networking library that is optimised for peer-to-peer connections and data transportation. It implements primitives to connect two peers together and start exchanging messages in a secure, reliable way. It supports **multiple protocols** ([UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) and [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) hole-punching) and it is crypto secure - all communications, starting with handshake messages, are encrypted. It also provides other security features like randomised ports that are used to prevent targeting a particular known port to conduct DoS attacks. Crust implements several [NAT traversal](https://en.wikipedia.org/wiki/NAT_traversal) techniques such as hole punching and use of [IGD](https://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol).


<a name="features"></a>
## Upcoming Features / Benefits

<a name="multiprotocol"></a>
### Multi-protocol expansion
Adding to the existing TCP & UDP hole-punching protocols Crust will soon include TCP-direct and introduce µTP, which wraps UDP and adds reliability, congestion control and ordered delivery to make a more robust and a better paradigm. Supporting multiple protocols means that if a firewall/router does not support one particular protocol then the network switches to another to get connected. If the firewall/router supports all protocols then Crust chooses the 1st protocol that successfully establishes the connection.

<a name="serialisation"></a>
### Secure serialisation
The network encrypts everything handed to it for transportation automatically. With Secure serialisation we have negated MITM attack as everything on the network is encrypted at each network hop. Also, the node signing each packet provides non-repudiation as the sender cannot deny that they signed the packet.

<a name="bootstrap"></a>
### Bootstrap cache
Bootstrap caching enhances the concept of using genesis nodes (hard-coded addresses) for initial vault detection by dynamically creating a list of nodes which are directly reachable without the need to hole-punch. This list is appended and pruned as nodes connect/disconnect to the network so is always kept up-to-date.

<a name="license"></a>
## License
This Crust library is dual-licensed under the Modified BSD ( [LICENSE-BSD](https://opensource.org/licenses/BSD-3-Clause)) or the MIT license ( [LICENSE-MIT](http://opensource.org/licenses/MIT)) at your option.

<a name="contribute"></a>
## Contribute
Copyrights in the SAFE Network are retained by their contributors. No copyright assignment is required to contribute to this project.
