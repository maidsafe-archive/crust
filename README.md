# Crust

Reliable p2p network connections in Rust with NAT traversal. One of the most needed libraries for any server-less, decentralised project.

|Crate|Documentation|Linux/OS X|Windows|Issues|
|:---:|:-----------:|:--------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/crust)](https://crates.io/crates/crust)|[![Documentation](https://docs.rs/crust/badge.svg)](https://docs.rs/crust)|[![Build Status](https://travis-ci.org/maidsafe/crust.svg?branch=master)](https://travis-ci.org/maidsafe/crust)|[![Build status](https://ci.appveyor.com/api/projects/status/ajw6ab26p86jdac4/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/crust/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/crust.png?label=ready&title=Ready)](https://waffle.io/maidsafe/crust)|

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

<a name="building"></a>
## Building from Source

### Using Cargo
As per any standard Rust library, Crust can be built using Cargo. This involves setting up a [Rust installation](https://www.rust-lang.org/en-US/install.html) on the target environment and platform. In addition to this, a GCC environment is also required. Setup of that depends on the platform:

* Linux: install the `build-essentials` package for your distribution
* OSX: install the 'Command Line Tools for XCode' package from the Apple Developer site or use [Homebrew](https://formulae.brew.sh/formula/gcc)
* Windows: get an installation of MinGW via [MSYS2](http://www.msys2.org/) or [Git Bash for Windows](https://gitforwindows.org/)

On Windows it is also possible to build with the Microsoft C++ toolchain, but using MinGW is the preferred method. Setting up the Microsoft C++ environment is beyond the scope of this document.

With that environment setup, on Linux or OSX, it should be as simple as cloning this repository then running `cargo build`. On Windows, it's slightly different:

* Use `rustup` to install the GNU target: `rustup target add x86_64-pc-windows-gnu`
* Specify this target when invoking Cargo: `cargo build --target x86_64-pc-windows-gnu`

### Using Docker

This repository also provides a Dockerfile that defines a container that has the prerequisites necessary for building Crust. To run this, install Docker on your host machine, then either pull the container or build it on the host. If you want to build it, there's a utility Makefile with a `build-container` target. If you're happy to work with the existing container, simply run `make run-container-build`, which will pull in the container then run it; this will build the current code and run the tests.

If you want to debug a build or get access to the artifacts produced, do the following:

* Run `make run-container-build-debug` from your host; this will give you shell access in the container.
* Run `cargo test --release --verbose` from the shell in the container.
* With the shell access in the container, you can debug any problems with the build.
* If you need access to the build artifacts, these will be available in the `target` directory on your host, since the current directory is mounted in as a shared volume.
* Exit the container to return back to the host shell.

<a name="license"></a>
## License
This Crust library is dual-licensed under the Modified BSD ( [LICENSE-BSD](https://opensource.org/licenses/BSD-3-Clause)) or the MIT license ( [LICENSE-MIT](http://opensource.org/licenses/MIT)) at your option.

<a name="contribute"></a>
## Contribute
Copyrights in the SAFE Network are retained by their contributors. No copyright assignment is required to contribute to this project.
