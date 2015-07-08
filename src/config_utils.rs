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

use transport::{Endpoint, Port};
use std::fs::File;
use std::io::prelude::*;
use std::path;
use std::path::PathBuf;
use std::env;
use rustc_serialize::json;
use std::io;
use std::convert::AsRef;

#[derive(PartialEq, Eq, Hash, Debug, Clone, RustcDecodable, RustcEncodable)]
pub struct Contact {
    pub endpoint: Endpoint,
}

pub type Contacts = Vec<Contact>;


#[derive(PartialEq, Debug, RustcDecodable, RustcEncodable)]
pub struct Config {
    pub preferred_port: Port,
    pub hard_coded_contacts: Contacts,
    pub beacon_port: u16,
}

pub fn default_config_path() -> io::Result<(PathBuf)> {
    let current_exe_path = try!(env::current_exe());
    let exe_name = try!(current_exe_path.file_name()
        .ok_or_else(||io::Error::new(io::ErrorKind::Other, format!("Failed to read current exe file name"))));
    let mut config_name: PathBuf = PathBuf::from(exe_name.to_os_string());;
    config_name.set_extension("config");
    let mut current_dir = try!(env::current_dir());
    current_dir.push(config_name);
    Ok(current_dir)
}

pub fn read_config_file(file_name : &PathBuf) -> io::Result<(Config)> {
    let mut file = try!(File::open(file_name));
    let mut contents = String::new();
    let _ = try!(file.read_to_string(&mut contents));
    json::decode(&contents)
         .map_err(|error| io::Error::new(io::ErrorKind::Other,
                                         format!("Failed to decode config file: {}", error)))
}

pub fn write_config_file(file_name : &PathBuf, config: &Config) -> io::Result<()> {
    let mut file = try!(File::create(file_name));
    try!(write!(&mut file, "{}", json::as_pretty_json(&config)));
    file.sync_all()
}


#[cfg(test)]
mod test {
    use super::*;
    use std::net;
    use std::net::SocketAddr;
    use transport::{Endpoint, Port};
    use rustc_serialize::json;
    use std::fs;
    use rand;
    use std::path::Path;

    #[test]
    fn read_config_file_test() {
        let mut hard_coded_contacts = Vec::new();
        for _ in 0..10 {
            let mut random_addr_0 = Vec::with_capacity(4);
            random_addr_0.push(rand::random::<u8>());  // FIXME (Prakash) move to utility
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());

            let port_0: u16 = rand::random::<u16>();
            let addr_0 = net::SocketAddrV4::new(net::Ipv4Addr::new(random_addr_0[0],
                random_addr_0[1], random_addr_0[2], random_addr_0[3]), port_0);
            let new_contact = Contact{ endpoint: Endpoint::Tcp(SocketAddr::V4(addr_0)) };
                hard_coded_contacts.push(new_contact);
        }
        let config = Config{ preferred_port: Port::Tcp(rand::random::<u16>()),
                             hard_coded_contacts: hard_coded_contacts,
                             beacon_port: rand::random::<u16>(),
                           };

        let file_name = default_config_path().unwrap(); // FIXME
        assert_eq!(write_config_file(&file_name, &config).ok(), Some(()));
        assert_eq!(read_config_file(&file_name).ok(), Some(config));
        default_config_path();
    }
}
