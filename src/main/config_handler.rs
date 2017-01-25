// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.


use common::{IpAddr, SocketAddr};
use config_file_handler::{self, FileHandler};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::PathBuf;

/// Bootstrap config
#[derive(PartialEq, Eq, Debug, RustcDecodable, RustcEncodable, Clone)]
pub struct Config {
    /// Direct contacts one should connect to
    pub hard_coded_contacts: Vec<SocketAddr>,
    /// Port for TCP acceptor
    pub tcp_acceptor_port: Option<u16>,
    /// Port for service discovery on local network
    pub service_discovery_port: Option<u16>,
    /// File for bootstrap cache
    pub bootstrap_cache_name: Option<String>,
    /// Bootstrap whitelisted IPs
    pub bootstrap_whitelisted_ips: HashSet<IpAddr>,
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
            service_discovery_port: None,
            bootstrap_cache_name: None,
            bootstrap_whitelisted_ips: HashSet::new(),
            network_name: None,
        }
    }
}

/// Reads the default crust config file.
pub fn read_config_file() -> ::Res<Config> {
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
#[allow(unused)]
pub fn write_config_file(hard_coded_contacts: Option<Vec<SocketAddr>>) -> ::Res<PathBuf> {
    use std::io::Write;

    let mut config = Config::default();

    if let Some(contacts) = hard_coded_contacts {
        config.hard_coded_contacts = contacts;
    }

    let mut config_path = config_file_handler::current_bin_dir()?;
    config_path.push(get_file_name()?);
    let mut file = ::std::fs::File::create(&config_path)?;
    write!(&mut file,
           "{}",
           ::rustc_serialize::json::as_pretty_json(&config))?;
    file.sync_all()?;
    Ok(config_path)
}

fn get_file_name() -> ::Res<OsString> {
    let mut name = config_file_handler::exe_file_stem()?;
    name.push(".crust.config");
    Ok(name)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_sample_config_file() {
        use std::path::Path;
        use std::io::Read;
        use super::Config;
        use rustc_serialize::json;

        let path = Path::new("installer/sample.config").to_path_buf();

        let mut file = match ::std::fs::File::open(path) {
            Ok(file) => file,
            Err(what) => {
                panic!(format!("CrustError opening sample.config: {:?}", what));
            }
        };

        let mut encoded_contents = String::new();

        if let Err(what) = file.read_to_string(&mut encoded_contents) {
            panic!(format!("CrustError reading sample.config: {:?}", what));
        }

        if let Err(what) = json::decode::<Config>(&encoded_contents) {
            panic!(format!("CrustError parsing sample.config: {:?}", what));
        }
    }
}
