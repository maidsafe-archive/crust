# Process for Connecting
The `ConnectionManager` will be the class which establishes and maintains connections between peers.  This document describes the internal processes which occur when `ConnectionManager::connect` is called.

### TCP
The intention is that the process for two peers to connect is asymmetric.  In other words, both peers can call `connect` to each other concurrently, but only one of the two `ConnectionManager`s actually initiates the connection attempt.  This avoids the issue of having to support the case where two peers establish duplicated connections between themselves.

So, if the `ConnectionManager` has no known endpoints of its own (i.e. it has just started up) the connection attempt is always made as the peer will be unaware of the other and won't be trying to connect concurrently.

If the `ConnectionManager` has at least one endpoint of its own, then we decide whether to attempt to connect based on which peer has the ‘lowest’ endpoint out of the two vectors of endpoints.  The definition of lowest in this context doesn't really matter, but we do need both peers to be looking at the same two vectors for the process to be valid.

### UTP
To be confirmed, but it is anticipated that UTP handles rendezvous connect natively, so newly-joining nodes can just call `utp::connect` and in all other cases the attempted connection will be triggered by both peers concurrently calling `utp::rendezvous_connect`.

### General
Once a connection is established, the `Event::NewConnection` should be triggered.  Failed attempts are not notified back up to the caller.  If the caller wants to know of a failed attempt, it must maintain a record of the attempt itself which times out if a corresponding `Event::NewConnection` isn't received.

### Unresolved issues
* For TCP, if two peers are basing their decision to actually attempt a connect on differing values of endpoint vectors, then both could either choose to not connect, or both could choose to try and connect.  Neither scenario is desirable, but the latter is exactly what this library looks to avoid.

* Again for TCP, if one peer is behind a router which disallows incoming connections and the other is not, by only allowing the connection attempt to happen in one direction (the lower connects to the higher), we have an increased chance of peers being unable to connect.
