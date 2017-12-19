// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use config_file_handler::{self, FileHandler};
use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use maidsafe_utilities::thread;
use notify::{self, Watcher};

use priv_prelude::*;
use rand;
use std;
use std::env;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tiny_keccak::sha3_256;

/// A handle to a crust config file. This handle can be cloned and shared throughout the program.
#[derive(Clone)]
pub struct ConfigFile {
    inner: Arc<RwLock<ConfigWrapper>>,
}

impl ConfigFile {
    /// Open a crust config file with the give file name.
    pub fn open_path(file_name: PathBuf) -> Result<ConfigFile, CrustError> {
        let thread_name = format!("monitor {:?}", file_name);

        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = notify::watcher(tx, Duration::from_secs(1))?;

        let (config_wrapper, real_path) = ConfigWrapper::open(file_name)?;
        watcher.watch(
            &real_path,
            notify::RecursiveMode::NonRecursive,
        )?;

        let inner = Arc::new(RwLock::new(config_wrapper));
        let weak = Arc::downgrade(&inner);
        let joiner = thread::named(thread_name, move || {
            for _event in rx {
                match weak.upgrade() {
                    Some(inner) => {
                        let mut inner = unwrap!(inner.write());
                        match inner.reload() {
                            Ok(()) => (),
                            Err(e) => {
                                error!("config refresher raised an error: {}", e);
                                return;
                            }
                        }
                    }
                    None => return,
                };
            }
            drop(watcher);
        });
        joiner.detach();
        Ok(ConfigFile { inner })
    }

    /// Open a crust config file with the default file name.
    pub fn open_default() -> Result<ConfigFile, CrustError> {
        ConfigFile::open_path(Self::get_default_file_name()?)
    }

    /// Get the file name of the default config file.
    pub fn get_default_file_name() -> Result<PathBuf, CrustError> {
        let mut name = config_file_handler::exe_file_stem()?;
        name.push(".crust.config");
        Ok(name.into())
    }

    /// Create a new, temporary config file and return a handle to it. This is mainly useful for
    /// tests.
    pub fn new_temporary() -> Result<ConfigFile, CrustError> {
        let file_name = format!("{:016x}.crust.config", rand::random::<u64>());
        let mut path = env::temp_dir();
        path.push(file_name);
        let file_handler = FileHandler::<ConfigSettings>::new(&path, true)?;
        drop(file_handler);

        Self::open_path(path)
    }

    /// Lock the config for reading.
    pub fn read(&self) -> ConfigReadGuard {
        ConfigReadGuard { guard: unwrap!(self.inner.read()) }
    }

    /// Lock the config for writing. Any changes made to the config will be synced to disc when the
    /// returned guard is dropped.
    pub fn write(&self) -> Result<ConfigWriteGuard, CrustError> {
        let guard = unwrap!(self.inner.write());
        let file_handler = FileHandler::new(&guard.file_name, false)?;
        Ok(ConfigWriteGuard {
            file_handler: file_handler,
            guard: guard,
        })
    }

    /// Reload the config file from disc.
    pub fn reload(&self) -> Result<(), CrustError> {
        let mut inner = unwrap!(self.inner.write());
        inner.reload()
    }

    /// Get the full path to the file.
    pub fn get_file_path(&self) -> Result<PathBuf, CrustError> {
        let config_wrapper = unwrap!(self.inner.read());
        let file_handler = FileHandler::<ConfigSettings>::new(&config_wrapper.file_name, false)?;
        Ok(file_handler.path().to_owned())
    }

    /// Get the name hash of the network we're configured to connect to.
    pub fn network_name_hash(&self) -> NameHash {
        match self.read().network_name {
            Some(ref name) => sha3_256(name.as_bytes()),
            None => [0; HASH_SIZE],
        }
    }

    /// Check whether an IP address is whitelisted. If whitelisting is disabled then all IPs are
    /// treated as being whitelisted.
    pub fn is_peer_whitelisted(&self, ip: IpAddr, peer_kind: CrustUser) -> bool {
        let res = {
            let config = self.read();
            let whitelist_opt = match peer_kind {
                CrustUser::Node => config.whitelisted_node_ips.as_ref(),
                CrustUser::Client => config.whitelisted_client_ips.as_ref(),
            };
            match whitelist_opt {
                None => true,
                Some(whitelist) => whitelist.contains(&ip),
            }
        };

        if !res {
            trace!("IP: {} is not whitelisted.", ip);
        }

        res
    }

    /// Attach an observer to this config. Observers will be notified via the returned channel
    /// whenever a change is made to the config.
    pub fn observe(&self) -> UnboundedReceiver<()> {
        let (tx, rx) = mpsc::unbounded();
        let mut inner = unwrap!(self.inner.write());
        inner.observers.push(tx);
        rx
    }
}

impl fmt::Debug for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inner = unwrap!(self.inner.read());
        fmt::Debug::fmt(&inner, f)
    }
}

/// Returned by `ConfigFile::read`. Locks the config for reading and be used to access the config
/// settings.
pub struct ConfigReadGuard<'c> {
    guard: RwLockReadGuard<'c, ConfigWrapper>,
}

impl<'c> Deref for ConfigReadGuard<'c> {
    type Target = ConfigSettings;

    fn deref(&self) -> &ConfigSettings {
        &self.guard.cfg
    }
}

/// Returned by `ConfigFile::write`. Locks the config for reading/writing and be used to mutate the
/// config settings. Any changes made to the settings will be synced to disc when then guard is
/// dropped.
pub struct ConfigWriteGuard<'c> {
    file_handler: FileHandler<ConfigSettings>,
    guard: RwLockWriteGuard<'c, ConfigWrapper>,
}

impl<'c> Deref for ConfigWriteGuard<'c> {
    type Target = ConfigSettings;

    fn deref(&self) -> &ConfigSettings {
        &self.guard.cfg
    }
}

impl<'c> DerefMut for ConfigWriteGuard<'c> {
    fn deref_mut(&mut self) -> &mut ConfigSettings {
        &mut self.guard.cfg
    }
}

impl<'c> Drop for ConfigWriteGuard<'c> {
    fn drop(&mut self) {
        match self.file_handler.write_file(&self.guard.cfg) {
            Ok(()) => (),
            Err(e) => {
                error!(
                    "Unable to write config file {:?}: {}",
                    self.guard.file_name,
                    e
                );
            }
        };
    }
}

#[derive(Default, Debug)]
struct ConfigWrapper {
    cfg: ConfigSettings,
    file_name: PathBuf,
    observers: Vec<UnboundedSender<()>>,
}

impl ConfigWrapper {
    /// Open the file and turn it into a `ConfigWrapper`. The returned `PathBuf` is full path to
    /// the file.
    fn open(file_name: PathBuf) -> Result<(ConfigWrapper, PathBuf), CrustError> {
        let (config, path) = ConfigSettings::open(&file_name)?;
        Ok((
            ConfigWrapper {
                cfg: config,
                file_name: file_name,
                observers: Vec::new(),
            },
            path,
        ))
    }

    fn reload(&mut self) -> Result<(), CrustError> {
        let file_handler = FileHandler::new(&self.file_name, false)?;
        let new_config = file_handler.read_file()?;
        let modified = self.cfg != new_config;
        if modified {
            self.cfg = new_config;
            self.observers.retain(
                |observer| observer.unbounded_send(()).is_ok(),
            );
        }
        Ok(())
    }
}

/// Crust configuration settings
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct ConfigSettings {
    /// Direct contacts one should connect to
    pub hard_coded_contacts: Vec<PaAddr>,
    /// Addresses that we listen on by default.
    pub listen_addresses: Vec<PaAddr>,
    /// Force usage of `tcp_acceptor_port` as our router mapped port. Normally if there is a port
    /// forwarding, crust will find out what the external world sees our local tcp acceptor
    /// endpoint as and include this information in our connection info that we share with others.
    /// However there are routers/firewalls in the wild which behave differently when a port is
    /// forwarded. They allow inbound connection through the forwarded port, but all outbound
    /// connections through the forwarded port get remapped to some ephemeral port. This prevents
    /// crust from knowing what the world sees our `tcp_acceptor_port` as because outbound
    /// connections get remapped although the port had been forwarded. In such scenarios, the user
    /// can specify this value as true, which will force crust to add the above `tcp_acceptor_port`
    /// to one of our externally reachable endpoint.
    pub force_acceptor_port_in_ext_ep: bool,
    /// Port for service discovery on local network
    pub service_discovery_port: Option<u16>,
    /// File for bootstrap cache
    pub bootstrap_cache_name: Option<PathBuf>,
    /// Whitelisted nodes who are allowed to bootstrap off us or to connect to us
    pub whitelisted_node_ips: Option<HashSet<IpAddr>>,
    /// Whitelisted clients who are allowed to bootstrap off us
    pub whitelisted_client_ips: Option<HashSet<IpAddr>>,
    /// Network ID
    ///
    /// This is a mechanism to prevent nodes from different decentralized
    /// networks to connect to each other (issue #209)
    pub network_name: Option<String>,
    /// Optional developer configuration
    pub dev: Option<DevConfigSettings>,
}

/// Developer options
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct DevConfigSettings {
    /// If `true`, then the mandatory external reachability test is disabled.
    pub disable_external_reachability_requirement: bool,
    /// If `true` then TCP is disabled
    pub disable_tcp: bool,
}

impl Default for ConfigSettings {
    fn default() -> ConfigSettings {
        ConfigSettings {
            hard_coded_contacts: vec![],
            listen_addresses: vec![],
            force_acceptor_port_in_ext_ep: false,
            service_discovery_port: None,
            bootstrap_cache_name: None,
            whitelisted_node_ips: None,
            whitelisted_client_ips: None,
            network_name: None,
            dev: None,
        }
    }
}

impl ConfigSettings {
    /// Open and deserialize the file. The returned `PathBuf` is full path to the file.
    fn open(file_name: &Path) -> Result<(ConfigSettings, PathBuf), CrustError> {
        let file_handler = FileHandler::new(file_name, false)?;
        let cfg = file_handler.read_file()?;
        let path = file_handler.path().to_owned();
        Ok((cfg, path))
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigFile;
    use config_file_handler;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn parse_sample_config_file() {
        let sample_name = "sample.config";

        let mut source = PathBuf::from("installer");
        let mut dest = unwrap!(config_file_handler::current_bin_dir());

        let mut target_dir = dest.clone();
        target_dir.push(&source);
        unwrap!(fs::create_dir_all(&target_dir));

        source.push(sample_name);
        dest.push(&source);

        unwrap!(fs::copy(&source, &dest));

        let _ = unwrap!(ConfigFile::open_path(source));
    }
}
