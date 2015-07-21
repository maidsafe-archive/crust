### Configuration file path
#### Naming convention
File name needs to be of the format : `[current_executable_name].config`
For crust_peer example, the config file name will be `crust_peer.config`


####Reading order
On construction of `crust::connection_manager` instance, crust will try to read configuration file from the following path in same order.

1. Current executable directory: using `std::env::current_exe`
2. Current user's application directory:  `UserAppDir`
3. Application support directory for all users: `SystemAppSupportDir `


Pro`s:
- Intermediate layer libraries need not to know anything about networking configuration.
- Installers can create the config file at appropriate path with desired name and permissions.
- Tests can override other paths by placing config file in current directory.
- File name format helps in separating config file of different application.

Cons:
- Running parallel tests will interfere each other.
- Multiple instances of same application cannot have customised config option per instance.
- Any user can override existing `SystemAppSupportDir ` config file by creating `UserAppDir`
 -
####Writing order
In case the configuration file is missing at all above paths, crust will attempt to create file at following path in same order.

1. Application support directory for all users: `SystemAppSupportDir `
2. Current user's application directory:  `UserAppDir`

#####Pro`s
- Application's advance users can modify config easily by altering the file
- Apps not having permissions for creating `SystemAppSupportDir ` will create `UserAppDir` after failing to create `SystemAppSupportDir `. This means crust stays agnostic of type of application (Client or Vault)
- If config options are default for an application, its installer can skip installing it and application will auto create appropriate file at best path if it can.
#####Cons:

 - If its a client user app having permissions to write to system dir, it will create system dir and not home dir
 -

#### Platform specific paths
**UserAppDir**
 - *Windows* - `env::var("APPDATA") / CompanyName() / ApplicationName()`
 - *APPLE* - `env::home_dir() / "Library/Application Support" / CompanyName() / ApplicationName()`
 - *Linux* -  `env::home_dir() / ".config" / CompanyName() / ApplicationName()`

**SystemAppSupportDir**
 - *Windows* - `env::var("ALLUSERSPROFILE") / CompanyName() / ApplicationName()`
 - *Apple* - `"/Library/Application Support/" / CompanyName() / ApplicationName()`
 - *Linux* - `"/opt/" / CompanyName() / "sbin"`

### Bootstrap cache file path


