# CRUST - Change Log

## [0.1.3]
- Travis document generation build script updated

## [0.1.2]
- Fixed documentation links

## [0.1.1]
- Removed sodiumoxide dependency

## [0.1.0]

## [0.0.66]
- [#140] (https://github.com/maidsafe/crust/issues/140) Bootstrap file format

## [0.0.65]
- [#148] (https://github.com/maidsafe/crust/issues/148) Ensure contents of Bootstrap file are unique Fixes
- [#151] (https://github.com/maidsafe/crust/issues/151) fix build failures with rust nightly

## [0.0.64]
- Code clean up

## [0.0.63]
- [#134] (https://github.com/maidsafe/crust/issues/134) First node doesn't read its own bootstrap list

## [0.0.62]
- [MAID-1125] (https://maidsafe.atlassian.net/browse/MAID-1125) Update Bootstrap Handler to use Json format.

## [0.0.61]
- [MAID-1124] (https://maidsafe.atlassian.net/browse/MAID-1124) Get a list of public IPs for others to connect to

## [0.0.60]
- [MAID-1075] (https://maidsafe.atlassian.net/browse/MAID-1075) Correct bug; listening on local port (127.0.0.1)
- [MAID-1122] (https://maidsafe.atlassian.net/browse/MAID-1122) Windows ifaddr resolution


## [0.0.1 - 0.0.8]
- Remove FailedToConnect Event
- Update process for Connecting in TCP
- Tcp Networking
  -  Tcp live port and backup random port selection
  -  Create send/rcv channel from routing to connections object
  -  Implement test for basic "hello world" two way communication
  -  Set up Udp broadcast and respond when we have a port (we listen on any random port above 1024 [user space port])  available (broadcast port is 5483)
  -  Add connection established/lost/ new messages to be passed to routing (via channel)
  -  Implement connect() in connection manager
  -  Allow tcp and then utp connections option and wrap in connection object.
  ](http://maidsafe.net/Whitepapers/pdf/DHTbasedNATTraversal.pdf)
-  Update handle connect for TCP
-  Remove FailedToConnect event
-  Integrate bootstrap (Link ability to read and write bootstrap file)
-  Integrate beacon (Have connection manger start, broadcast on udp broadcast for port 5483 (later multicast for ipv6)
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
