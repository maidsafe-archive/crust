// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::PeerInfo;
use config_file_handler::{self, FileHandler};
use std::collections::HashSet;
use std::ffi::OsString;
use std::net::IpAddr;

#[cfg(test)]
use std::path::PathBuf;

/// Crust configuration settings
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Direct contacts one should connect to
    pub hard_coded_contacts: Vec<PeerInfo>,
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
    /// Port for service discovery on local network. This port is used to broadcast messages to.
    pub service_discovery_port: Option<u16>,
    /// You can configure service discovery server to listen on a separate port. This becomes
    /// useful when you want to run multiple instances of Crust on the same machine.
    /// By default it will use the same as `service_discovery_port` value.
    pub service_discovery_listener_port: Option<u16>,
    /// File for bootstrap cache
    pub bootstrap_cache_name: Option<OsString>,
    /// Whitelisted nodes who are allowed to bootstrap off us or to connect to us
    pub whitelisted_node_ips: Option<HashSet<IpAddr>>,
    /// Whitelisted clients who are allowed to bootstrap off us
    pub whitelisted_client_ips: Option<HashSet<IpAddr>>,
    /// Network ID
    ///
    /// This is a mechanism to prevent nodes from different decentralized
    /// networks to connect to each other (issue #209)
    pub network_name: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            hard_coded_contacts: vec![],
            tcp_acceptor_port: None,
            force_acceptor_port_in_ext_ep: false,
            service_discovery_port: None,
            service_discovery_listener_port: None,
            bootstrap_cache_name: None,
            whitelisted_node_ips: None,
            whitelisted_client_ips: None,
            network_name: None,
        }
    }
}

/// Reads the default crust config file.
pub fn read_config_file() -> crate::Res<Config> {
    let file_handler = FileHandler::new(&get_file_name()?, false)?;
    let cfg = file_handler.read_file()?;
    Ok(cfg)
}

/// Writes a Crust config file **for use by tests and examples**.
///
/// The file is written to the [`current_bin_dir()`](file_handler/fn.current_bin_dir.html)
/// with the appropriate file name.
///
/// N.B. This method should only be used as a utility for test and examples.  In normal use cases,
/// this file should be created by the installer for the dependent application.
#[cfg(test)]
#[allow(dead_code)]
pub fn write_config_file(hard_coded_contacts: Option<Vec<PeerInfo>>) -> crate::Res<PathBuf> {
    use serde_json;
    use std::io::Write;

    let mut config = Config::default();

    if let Some(contacts) = hard_coded_contacts {
        config.hard_coded_contacts = contacts;
    }

    let mut config_path = config_file_handler::current_bin_dir()?;
    config_path.push(get_file_name()?);
    let mut file = ::std::fs::File::create(&config_path)?;
    write!(
        &mut file,
        "{}",
        unwrap!(serde_json::to_string_pretty(&config))
    )?;
    file.sync_all()?;
    Ok(config_path)
}

fn get_file_name() -> crate::Res<OsString> {
    let mut name = config_file_handler::exe_file_stem()?;
    name.push(".crust.config");
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::Config;
    use serde_json;
    use std::io::Read;
    use std::path::Path;

    #[test]
    fn parse_sample_config_file() {
        let path = Path::new("installer/sample.config").to_path_buf();

        let mut file = match ::std::fs::File::open(path) {
            Ok(file) => file,
            Err(what) => panic!(format!("CrustError opening sample.config: {:?}", what)),
        };

        let mut encoded_contents = String::new();

        if let Err(what) = file.read_to_string(&mut encoded_contents) {
            panic!(format!("CrustError reading sample.config: {:?}", what));
        }

        if let Err(what) = serde_json::from_str::<Config>(&encoded_contents) {
            panic!(format!("CrustError parsing sample.config: {:?}", what));
        }
    }
}
