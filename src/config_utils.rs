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

// pub fn default_config_path() -> io::Result<(PathBuf)> {
//     let current_exe_path = try!(env::current_exe());
//     let exe_name = try!(current_exe_path.file_name()
//         .ok_or_else(||io::Error::new(io::ErrorKind::Other, format!("Failed to read current exe file name"))));
//     let mut config_name: PathBuf = PathBuf::from(exe_name.to_os_string());;
//     config_name.set_extension("config");
//     let mut current_dir = try!(env::current_dir());
//     current_dir.push(config_name);
//     Ok(current_dir)
// }

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

pub fn read_or_create_config() -> io::Result<(Config)> {
    let res = read_config_file();
    if res.is_ok() {
        return res;
    }
    try!(write_default_config_file());
    read_config_file()
}

// Try reading in following order:
// Current executable directory: using std::env::current_exe
// Current user's application directory: UserAppDir
// Application support directory for all users: SystemAppSupportDir
#[allow(dead_code)]
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
    read_file(&file_path)
}

pub fn write_default_config_file() -> io::Result<()> {
    let file_name = try!(get_file_name());

    // Default Config
    let config = Config{ override_default_bootstrap: false,
                         hard_coded_contacts: vec![],
                         beacon_port: 0u16,
                       };


    // Application support directory for all users
    let file_path = utils::system_app_support_dir().unwrap().join(&file_name);
    let res = write_file(&file_path, &config);
    if res.is_ok() {
        return res;
    }

    // Current user's application directory
    let file_path = utils::user_app_dir().unwrap().join(file_name);
    write_file(&file_path, &config)
}


pub fn read_file(file_name : &PathBuf) -> io::Result<(Config)> {
    let mut file = try!(File::open(file_name));
    let mut contents = String::new();
    let _ = try!(file.read_to_string(&mut contents));
    json::decode(&contents)
         .map_err(|error| io::Error::new(io::ErrorKind::Other,
                                         format!("Failed to decode config file: {}", error)))
}

pub fn write_file(file_name : &PathBuf, config: &Config) -> io::Result<()> {
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

    let config = Config{ override_default_bootstrap: override_default_bootstrap.unwrap_or(false),
                         hard_coded_contacts: hard_coded_contacts,
                         beacon_port: beacon_port.unwrap_or(0u16),
                       };

    let config_path = try!(exe_path_config());
    try!(write_file(&config_path, &config));
    Ok(config_path)
}


#[cfg(test)]
mod test {
    use super::*;
    use std::net;
    use std::net::SocketAddr;
    use transport::{Endpoint, Port};
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
        assert_eq!(write_file(&file_name, &config).ok(), Some(()));
        assert_eq!(read_file(&file_name).ok(), Some(config));
        let _  = fs::remove_file(&file_name);
    }
}
