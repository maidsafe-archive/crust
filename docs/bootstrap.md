### Bootstrap Cache
Bootstrap cache file (JSON file) can be used to pass a few configuration information along with cache of previous connections and fall back endpoints information to Crust node.

It needs to be present in the directory the exe is run from (work dir). It name needs to be of the format :
`<current executable>.bootstrap.cache `
For crust_peer example, the bootstrap_file will be `crust_peer.bootstrap.cache`

File has following fields:
1. `preferred_port`: Crust node will try to start listening on this port on mentioned protocol variant (if supported). If the port is already aquired by some other process, then a random port is chosen.
2.  `hard_coded_contacts`: List of hardcoded endpoints. Crust when bootstrapping, will read and append these hardcoded endpoints to the acquired bootstrap endpoints by default methods (beacon & contacts field from bootstrap file). The hardcoded endpoints are to cater for fallback situations when a node can not connect to any other node using default methods.
3.  `contacts`: List of endpoints which is used (in addition to other default methods) when a crust node attempts to bootstrap off a network. This list is updated by the owner of the bootstrap file whenever it gets a new connection.

*Example of bootstrap cache file:*
```
{"preferred_port":{"variant":"Tcp","fields":[0]},"hard_coded_contacts":[{"endpoint":"192.168.0.10:51296"},{"endpoint":"192.168.0.10:5455"}],"contacts":[{"endpoint":"127.0.0.1:51296"},{"endpoint":"192.168.0.10:51296"},{"endpoint":"192.168.0.10:57545"}]}
```

**Starting a node on a specific port** (useful if the machine’s IP is publicly available)
Also useful and required for users who want to port forward their router (i.e. run tcp node at home). It is less safe though as you will always connect to the network on the same ports, but this is potentially a very small security issue and not of concern to many.

Update preferred_port to desired port and protocol variant (only TCP supported currently).
Example:  ``` "preferred_port":{"variant":"Tcp","fields":[5555]} ```

**Adding hardcoded endpoints to a bootstrap file** (bootstrap file should be packaged into the installer with only hard_coded_contacts field populated and keeping other fields empty)

```
"hard_coded_contacts":[{"endpoint":"192.168.0.10:51296"},{"endpoint":"192.168.0.10:5455"}],
```

**API change notes**
The API is preserved as previous version (0.0.62). ConnectionManager::start_listening2()  takes listening port as hint. This will work the same way and will override the preferred_port read from bootstrap file. So upper layers now need to start using the bootstrap file to pass hint field.
