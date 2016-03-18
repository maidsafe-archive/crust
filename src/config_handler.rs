// Copyright 2015 MaidSafe.net limited.
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

use static_contact_info::StaticContactInfo;
use config_file_handler::FileHandler;
use config_file_handler;
use socket_addr::SocketAddr;

#[derive(PartialEq, Eq, Debug, RustcDecodable, RustcEncodable, Clone)]
pub struct Config {
    pub hard_coded_contacts: Vec<StaticContactInfo>,
    pub enable_tcp: bool,
    pub enable_utp: bool,
    pub tcp_acceptor_port: Option<u16>,
    pub utp_acceptor_port: Option<u16>,
    pub udp_mapper_servers: Vec<SocketAddr>,
    pub tcp_mapper_servers: Vec<SocketAddr>,
    pub service_discovery_port: Option<u16>,
    pub bootstrap_cache_name: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            hard_coded_contacts: vec![], // No hardcoded endpoints
            enable_tcp: true,
            enable_utp: true,
            tcp_acceptor_port: None,
            utp_acceptor_port: None,
            udp_mapper_servers: vec![],
            tcp_mapper_servers: vec![],
            service_discovery_port: None,
            bootstrap_cache_name: None,
        }
    }
}

/// Reads the default crust config file.
pub fn read_config_file() -> Result<Config, ::error::Error> {
    let file_handler = try!(FileHandler::new(&try!(get_file_name())));
    let cfg = try!(file_handler.read_file());
    Ok(cfg)
}

/// Writes a Crust config file **for use by tests and examples**.
///
/// The file is written to the [`current_bin_dir()`](file_handler/fn.current_bin_dir.html)
/// with the appropriate file name.
///
/// N.B. This method should only be used as a utility for test and examples.  In normal use cases,
/// this file should be created by the installer for the dependent application.
pub fn write_config_file(hard_coded_contacts: Option<Vec<StaticContactInfo>>)
                         -> Result<::std::path::PathBuf, ::error::Error> {
    use std::io::Write;

    let mut config = Config::default();

    if let Some(contacts) = hard_coded_contacts {
        config.hard_coded_contacts = contacts;
    }

    let mut config_path = try!(config_file_handler::current_bin_dir());
    config_path.push(try!(get_file_name()));
    let mut file = try!(::std::fs::File::create(&config_path));
    try!(write!(&mut file,
                "{}",
                ::rustc_serialize::json::as_pretty_json(&config)));
    try!(file.sync_all());
    Ok(config_path)
}

fn get_file_name() -> Result<::std::ffi::OsString, ::error::Error> {
    let mut name = try!(config_file_handler::exe_file_stem());
    name.push(".crust.config");
    Ok(name)
}

#[cfg(test)]
mod test {
    // TODO(canndrew): Also add this test back
    //
    // #[test]
    // fn read_config_file_test() {
    // let mut hard_coded_endpoints = Vec::new();
    // let mut hard_coded_contacts = Vec::new();
    // for _ in 0..10 {
    // let random_contact = ::util::random_endpoint();
    // hard_coded_endpoints.push(random_contact.clone());
    // hard_coded_contacts.push(random_contact);
    // }
    // let config = super::Config { hard_coded_contacts: hard_coded_contacts };
    // let path_buf = unwrap_result!(super::write_config_file(Some(hard_coded_endpoints)));
    // match super::read_config_file() {
    // Ok(recovered_config) => assert_eq!(config, recovered_config),
    // Err(_) => panic!("Failed to read config file."),
    // }
    //
    // Clean up
    // match ::config_file_handler::current_bin_dir() {
    // Ok(mut config_path) => {
    // config_path.push(path_buf);
    // let _ = ::std::fs::remove_file(&config_path);
    // }
    // Err(_) => (),
    // };
    // }
    //


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
                panic!(format!("Error opening sample.config: {:?}", what));
            }
        };

        let mut encoded_contents = String::new();

        if let Err(what) = file.read_to_string(&mut encoded_contents) {
            panic!(format!("Error reading sample.config: {:?}", what));
        }

        if let Err(what) = json::decode::<Config>(&encoded_contents) {
            panic!(format!("Error parsing sample.config: {:?}", what));
        }
    }
}
