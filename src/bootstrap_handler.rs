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
use time;
use std::fs::File;
use std::io::prelude::*;
use std::path;
use std::env;
use rustc_serialize::json;
use std::io;
use itertools::Itertools;
use config_utils::{Contact, Contacts};


#[derive(PartialEq, Debug, RustcDecodable, RustcEncodable)]
pub struct Bootstrap {
    pub contacts: Contacts,
}

pub struct BootstrapHandler {
    file_name: String,
    last_updated: time::Tm,
}


pub fn serialise_contacts(contacts: Contacts) -> Vec<u8> {
    let encoded = json::encode(&contacts).unwrap();
    return encoded.into_bytes();
}

pub fn parse_contacts(buffer: Vec<u8>) -> Option<Contacts> {
    String::from_utf8(buffer).ok().and_then(|contacts_str| {
        json::decode(&contacts_str).ok()
    })
}



impl BootstrapHandler {
    pub fn get_file_name() -> String {
        let path = match env::current_exe() {
                Ok(exe_path) => exe_path,
                Err(e) => panic!("Failed to get current exe path: {}", e),
            };
        let name_with_extension = path.file_name().expect("Unknown filename");
        let name = path::Path::new(name_with_extension).file_stem()
            .expect("Unknown extension");

        let mut filename = String::new();
        filename.push_str("./");
        filename.push_str(name.to_str().unwrap());
        filename.push_str(".bootstrap.cache");
        filename
    }

    pub fn new() -> BootstrapHandler {
        BootstrapHandler {
            file_name: BootstrapHandler::get_file_name(),
            last_updated: time::now(),
        }
    }

    pub fn get_update_duration() -> time::Duration {
        time::Duration::hours(4)
    }

    pub fn add_contacts(&mut self, contacts: Vec<Contact>) -> io::Result<()> {
        try!(self.insert_contacts(contacts));
        // TODO(Team) this implementation is missing and should be considered in next planning
        if time::now() > self.last_updated + BootstrapHandler::get_update_duration() {
            // self.check_bootstrap_contacts();
        }
        Ok(())
    }

    pub fn read_bootstrap_file(&self) -> io::Result<(Bootstrap)> {
        let mut file = try!(File::open(&self.file_name));
        let mut contents = String::new();
        let _ = try!(file.read_to_string(&mut contents));
        json::decode(&contents)
             .map_err(|error| io::Error::new(io::ErrorKind::Other,
                                             format!("Failed to decode bootstrap file: {}", error)))
    }

    fn write_bootstrap_file(&mut self, mut bootstrap: Bootstrap) -> io::Result<()> {
        bootstrap.contacts = bootstrap.contacts.clone().into_iter().unique().collect();
        let mut file = try!(File::create(&self.file_name));
        try!(write!(&mut file, "{}", json::as_pretty_json(&bootstrap)));
        file.sync_all()
    }

    fn insert_contacts(&mut self, contacts: Contacts) -> io::Result<()> {
        assert!(!contacts.is_empty());

        let mut current_bootstrap = self.read_bootstrap_file()
            .unwrap_or_else(|e| {
                println!("Failed to read Bootstrap cache file : {:?} ; {:?} ; Creating New file.",
                self.file_name, e);
                Bootstrap{ contacts: Vec::new() }
            });

        for contact in contacts {
            current_bootstrap.contacts.push(contact.clone());
        }
        self.write_bootstrap_file(current_bootstrap)
    }

    pub fn get_serialised_contacts(&self) -> io::Result<(Vec<u8>)> {
        let bootstrap = try!(self.read_bootstrap_file());
        Ok(serialise_contacts(bootstrap.contacts))
    }
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
    use config_utils::{Contact, Contacts};

    #[test]
    fn serialisation() {
        let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(1,2,3,4), 8080);
        let contact  = Contact { endpoint: Endpoint::Tcp(SocketAddr::V4(addr)) };
        let mut contacts = Contacts::new();
        contacts.push(contact.clone());
        contacts.push(contact.clone());
        let bootstrap = Bootstrap { contacts: contacts };
        let encoded = json::encode(&bootstrap).unwrap();
        let decoded: Bootstrap = json::decode(&encoded).unwrap();
        assert_eq!(bootstrap, decoded);
    }

    #[test]
    fn bootstrap_handler_test() {
        let mut contacts = Vec::new();
        for _ in 0..10 {
            let mut random_addr_0 = Vec::with_capacity(4);
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());

            let port_0: u16 = rand::random::<u16>();
            let addr_0 = net::SocketAddrV4::new(net::Ipv4Addr::new(random_addr_0[0],
                random_addr_0[1], random_addr_0[2], random_addr_0[3]), port_0);
            let new_contact = Contact{ endpoint: Endpoint::Tcp(SocketAddr::V4(addr_0)) };
                contacts.push(new_contact);
        }

        let file_name = BootstrapHandler::get_file_name();
        let path = Path::new(&file_name);

        let mut bootstrap_handler = BootstrapHandler::new();
        let file = fs::File::create(&path);
        assert!(file.is_ok()); // Check whether the database file is created
        // Add Contacts
        assert!(bootstrap_handler.insert_contacts(contacts.clone()).is_ok());

        // Add duplicate contacts
        for _ in 1..100 {
            assert!(bootstrap_handler.insert_contacts(contacts.clone()).is_ok());
        }

        let read_bootstrap: Bootstrap = bootstrap_handler.read_bootstrap_file().unwrap();
        let read_contacts : Contacts = read_bootstrap.contacts;

        assert_eq!(read_contacts, contacts);

        match fs::remove_file(file_name.clone()) {
            Ok(_) => (),
            Err(e) => println!("Failed to remove {}: {}", file_name, e),
        };
    }
}
