### Configuration file path
#### Naming convention
File name needs to be of the format : `[current_executable_name].config`
For crust_peer example, the config file name will be `crust_peer.config`


####Reading order
On construction of `crust::connection_manager` instance, crust will try to read configuration file from the following path in same order.
1. Current executable directory: `std::env::current_exe`
2. Current user's application directory:  `UserAppDir`
3. Application support directory for all users: `SystemAppSupportDir `

#####Pro`s:

#####Cons:

####Writing order
In case the configuration file is missing at all above paths, crust will attempt to create file at following path in same order.
1. Application support directory for all users: `SystemAppSupportDir `
2. Current user's application directory:  `UserAppDir`

#####Pro`s

#####Cons:

 - If its a client user app having permissions to write to system dir, it will create system dir and not home dir

#### Platform specific paths
**UserAppDir**
 - *Windows* - `env::var("APPDATA") / CompanyName() / ApplicationName()`
 - *APPLE* - `env::home_dir() / "/Library/Application Support/" / CompanyName() / ApplicationName()`
 - *Linux* -  `env::home_dir() / ".config" / CompanyName() / ApplicationName()`

**SystemAppSupportDir**
 - *Windows* - `env::var("ALLUSERSPROFILE") / CompanyName() / ApplicationName()`
 - *Apple* - `"/Library/Application Support/" / CompanyName() / ApplicationName()`
 - *Linux* - `"/opt/" / CompanyName() / "sbin"`

### Bootstrap cache file path

