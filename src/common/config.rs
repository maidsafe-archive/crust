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
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::path::{PathBuf, Path};
use std::ops::{Deref, DerefMut};
use std::net::{SocketAddr, IpAddr};
use std::collections::HashSet;

/// A handle to a crust config file. This handle can be cloned and shared throughout the program.
#[derive(Clone)]
pub struct ConfigFile {
    inner: Arc<RwLock<ConfigWrapper>>,
}

impl ConfigFile {
    /// Open a crust config file with the give file name.
    pub fn open_path(file_name: PathBuf) -> ::Res<ConfigFile> {
        let config_wrapper = ConfigWrapper::open(file_name)?;
        Ok(ConfigFile {
            inner: Arc::new(RwLock::new(config_wrapper)),
        })
    }

    /// Open a crust config file with the default file name.
    pub fn open_default() -> ::Res<ConfigFile> {
        let mut name = config_file_handler::exe_file_stem()?;
        name.push(".crust.config");
        let config_wrapper = ConfigWrapper::open(name.into())?;
        Ok(ConfigFile {
            inner: Arc::new(RwLock::new(config_wrapper)),
        })
    }

    /// Lock the config for reading.
    pub fn read(&self) -> ConfigReadGuard {
        ConfigReadGuard {
            guard: unwrap!(self.inner.read()),
        }
    }

    /// Lock the config for writing. Any changes made to the config will be synced to disc when the
    /// returned guard is dropped.
    pub fn write(&self) -> ::Res<ConfigWriteGuard> {
        let guard = unwrap!(self.inner.write());
        let file_handler = FileHandler::new(&guard.file_name, false)?;
        Ok(ConfigWriteGuard {
            file_handler: file_handler,
            guard: guard,
        })
    }

    /// Reload the config file from disc and report if the file had been modified since it was
    /// last read/written.
    pub fn reload_and_check_modified(&self) -> ::Res<bool> {
        let mut current_config = unwrap!(self.inner.write());
        let file_handler = FileHandler::new(&current_config.file_name, false)?;
        let new_config = file_handler.read_file()?;
        let modified = current_config.cfg != new_config;
        if modified {
            current_config.cfg = new_config;
        }
        Ok(modified)
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

/// Returned by `ConfigFile::write`. Locks the config for reading/writing and be used to mutate the config
/// settings. Any changes made to the settings will be synced to disc when then guard is dropped.
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
                error!("Unable to write config file {:?}: {}", self.guard.file_name, e);
            },
        };
    }
}

#[derive(Default)]
struct ConfigWrapper {
    cfg: ConfigSettings,
    file_name: PathBuf,
}

impl ConfigWrapper {
    pub fn open(file_name: PathBuf) -> ::Res<ConfigWrapper> {
        let config = ConfigSettings::open(&file_name)?;
        Ok(ConfigWrapper {
            cfg: config,
            file_name: file_name,
        })
    }
}

/// Crust configuration settings
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct ConfigSettings {
    /// Direct contacts one should connect to
    pub hard_coded_contacts: Vec<SocketAddr>,
    /// Port for TCP acceptor
    pub tcp_acceptor_port: Option<u16>,
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
}

impl Default for ConfigSettings {
    fn default() -> ConfigSettings {
        ConfigSettings {
            hard_coded_contacts: vec![],
            tcp_acceptor_port: None,
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
    /// Open the given file name and read settings.
    pub fn open(file_name: &Path) -> ::Res<ConfigSettings> {
        let file_handler = FileHandler::new(file_name, false)?;
        let cfg = file_handler.read_file()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigFile;
    use std::fs;
    use config_file_handler;
    use std::path::PathBuf;

    #[test]
    fn parse_sample_config_file() {
        let sample_name = "sample.config";

        let mut source = PathBuf::from("installer");
        source.push(sample_name);
        let mut target = unwrap!(config_file_handler::current_bin_dir());
        target.push(sample_name);

        let _ = unwrap!(fs::copy(source, target));

        let path = PathBuf::from(sample_name);
        let _ = unwrap!(ConfigFile::open_path(path));
    }
}

