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

use transport::Endpoint;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::env;
use rustc_serialize::json;
use std::io;
use utils;

#[derive(PartialEq, Eq, Hash, Debug, Clone, RustcDecodable, RustcEncodable)]
pub struct Contact {
    pub endpoint: Endpoint
}

pub type Contacts = Vec<Contact>;

#[derive(PartialEq, Debug, RustcDecodable, RustcEncodable, Clone)]
pub struct Config {
    pub override_default_bootstrap: bool,
    pub hard_coded_contacts: Contacts,
    pub beacon_port: u16,
}

impl Config {

    pub fn make_default() -> Config {
        Config{ override_default_bootstrap: false,  // default bootstraping methods enabled
                hard_coded_contacts: vec![], // No hardcoded endpoints
                beacon_port: 5483u16, // LIVE port : crust's default
              }
    }
}

pub fn exe_path_config() -> io::Result<(PathBuf)> {
    let file_name = try!(get_file_name());
    let mut path = try!(env::current_exe());
    path.pop();
    let path = path.join(file_name.clone());
    Ok(path)
}

pub fn get_file_name() -> io::Result<(PathBuf)> {
    let current_exe_path = try!(env::current_exe());
    let file_stem = try!(current_exe_path.file_stem()
        .ok_or_else(||io::Error::new(io::ErrorKind::Other, format!("Failed to read current exe file name"))));
    let mut os_string = file_stem.to_os_string();
    os_string.push(".crust.config");
    Ok(PathBuf::from(os_string))
}

// Try reading in following order:
// Current executable directory: using std::env::current_exe
// Current user's application directory: UserAppDir
// Application support directory for all users: SystemAppSupportDir
pub fn read_config_file() -> io::Result<(Config)> {
    // Current executable directory
    let path = try!(exe_path_config());
    let res = read_file(&path);
    if res.is_ok() {
        return res;
    }

    let file_name = try!(get_file_name());

    // Current user's application directory
    let file_path = utils::user_app_dir().unwrap().join(&file_name);
    let res = read_file(&file_path);
    if res.is_ok() {
        return res;
    }

    // Application support directory for all users
    let file_path = utils::system_app_support_dir().unwrap().join(file_name);
    let res = read_file(&file_path);
    if res.is_ok() {
        return res;
    }

    Ok(Config::make_default())
}

fn read_file(file_name : &PathBuf) -> io::Result<(Config)> {
    let mut file = try!(File::open(file_name));
    let mut contents = String::new();
    let _ = try!(file.read_to_string(&mut contents));
    json::decode(&contents)
         .map_err(|error| io::Error::new(io::ErrorKind::Other,
                                         format!("Failed to decode config file: {}", error)))
}

fn write_file(file_name : &PathBuf, config: &Config) -> io::Result<()> {
    let mut file = try!(File::create(file_name));
    try!(write!(&mut file, "{}", json::as_pretty_json(&config)));
    file.sync_all()
}

/// Writes config file and parametes to exe directory with appropriate file name format
/// This method should be only used as a utility for test and examples
/// For installed application, this file should be created by installer.
pub fn write_config_file(override_default_bootstrap: Option<bool>,
                         hard_coded_endpoints: Option<Vec<Endpoint>>,
                         beacon_port: Option<u16>) -> io::Result<(PathBuf)> {
    let mut hard_coded_contacts: Contacts = vec![];
    match hard_coded_endpoints {
        Some(endpoints) => {
            for endpoint in endpoints {
                hard_coded_contacts.push(Contact{endpoint: endpoint });
            }
        },
        None => {}
    };
    let hard_coded_contacts = Some(hard_coded_contacts);

    let default = Config::make_default();

    let config = Config{ override_default_bootstrap: override_default_bootstrap
                            .unwrap_or(default.override_default_bootstrap),
                         hard_coded_contacts: hard_coded_contacts
                            .unwrap_or(default.hard_coded_contacts),
                         beacon_port: beacon_port
                            .unwrap_or(default.beacon_port),
                       };

    let mut config_path = try!(exe_path_config());
    match write_file(&config_path, &config) {
        Ok(()) => return Ok(config_path),
        Err(_) => {}
    }

    let file_name = try!(get_file_name());

    // Current user's application directory
    config_path = utils::user_app_dir().unwrap().join(&file_name);
    match write_file(&config_path, &config) {
        Ok(()) => return Ok(config_path),
        Err(_) => {}
    }

    // Application support directory for all users
    config_path = utils::system_app_support_dir().unwrap().join(file_name);
    match write_file(&config_path, &config) {
        Ok(()) => return Ok(config_path),
        Err(e) => Err(e)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net;
    use std::net::SocketAddr;
    use transport::Endpoint;
    use std::fs;
    use rand;

    #[test]
    fn read_config_file_test() {
        let mut hard_coded_contacts = Vec::new();
        for _ in 0..10 {
            let mut random_addr_0 = Vec::with_capacity(4);
            random_addr_0.push(rand::random::<u8>());  // TODO move to utility
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());

            let port_0: u16 = rand::random::<u16>();
            let addr_0 = net::SocketAddrV4::new(net::Ipv4Addr::new(random_addr_0[0],
                random_addr_0[1], random_addr_0[2], random_addr_0[3]), port_0);
            let new_contact = Contact { endpoint: Endpoint::Tcp(SocketAddr::V4(addr_0)) };
            hard_coded_contacts.push(new_contact);
        }
        let config = Config{ override_default_bootstrap: false,
                             hard_coded_contacts: hard_coded_contacts,
                             beacon_port: rand::random::<u16>(),
                           };

        let file_name = exe_path_config().unwrap();
        assert_eq!(super::write_file(&file_name, &config).ok(), Some(()));
        assert_eq!(super::read_file(&file_name).ok(), Some(config));
        let _  = fs::remove_file(&file_name);
    }
}
