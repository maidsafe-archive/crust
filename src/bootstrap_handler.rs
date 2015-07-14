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

use time;
use std::fs::File;
use std::io::prelude::*;
use std::path;
use std::env;
use rustc_serialize::json;
use std::io;
use itertools::Itertools;
use config_utils::{Contact, Contacts};

const MAX_CONTACTS: usize = 1500;

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
        let mut bootstrap = self.read_bootstrap_file()
            .unwrap_or_else(|e| {
                println!("Failed to read Bootstrap cache file : {:?} ; {:?} ; Creating New file.",
                self.file_name, e);
                Bootstrap{ contacts: Vec::new() }
            });

        let mut contact_list = contacts.clone();

        for contact in contacts {
            match bootstrap.contacts.binary_search_by(|e| e.endpoint.cmp(&contact.endpoint)) {
                Ok(position) => { let _ = bootstrap.contacts.remove(position); },
                Err(_) => {}
            }
        }

        for contact in bootstrap.contacts {
            contact_list.push(contact.clone());
        }

        let mut bootstrap_contacts = contact_list
            .into_iter()
            .sort_by(|a, b| Ord::cmp(&b.last_updated.timestamp, &a.last_updated.timestamp))
            .into_iter()
            .map(|contact| contact)
            .collect::<Vec<Contact>>();

        bootstrap_contacts.truncate(MAX_CONTACTS);
        bootstrap.contacts = bootstrap_contacts;

        self.write_bootstrap_file(bootstrap)
    }

    pub fn get_serialised_contacts(&self) -> io::Result<(Vec<u8>)> {
        let bootstrap = try!(self.read_bootstrap_file());
        Ok(serialise_contacts(bootstrap.contacts))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{net, fs};
    use std::net::{SocketAddr, Ipv4Addr};
    use transport::Endpoint;
    use rustc_serialize::json;
    use rand;
    use std::path::Path;
    use time;
    use itertools::Itertools;
    use cbor::{Encoder, Decoder};
    use rustc_serialize::{Decodable, Encodable};
    use config_utils::{Contact, Contacts, Timestamp};

    use super::MAX_CONTACTS;

    #[test]
    fn timestamp() {
        let time = time::now_utc();
        let timestamp = Timestamp{ timestamp: time };
        let mut timestamp_encoder = Encoder::from_memory();
        timestamp_encoder.encode(&[&timestamp]).unwrap();
        let mut timestamp_decoder = Decoder::from_bytes(timestamp_encoder.as_bytes());
        let decoded_timestamp: Timestamp = timestamp_decoder.decode().next().unwrap().unwrap();
        assert_eq!(timestamp, decoded_timestamp);
    }

    #[test]
    fn serialisation() {
        let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(1,2,3,4), 8080);
        let contact  = Contact {
            endpoint: Endpoint::Tcp(SocketAddr::V4(addr)),
            last_updated: Timestamp{ timestamp: time::empty_tm() }
        };
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
            let new_contact = Contact{
                endpoint: Endpoint::Tcp(SocketAddr::V4(addr_0)),
                last_updated: Timestamp{ timestamp: time::now_utc() }
            };
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

    #[test]
    fn bootstrap_handler_max_contacts() {
        let mut contacts = Vec::new();
        for _ in 0..MAX_CONTACTS {
            let mut ip = Vec::with_capacity(4);

            ip.push(rand::random::<u8>());
            ip.push(rand::random::<u8>());
            ip.push(rand::random::<u8>());
            ip.push(rand::random::<u8>());

            let port = rand::random::<u16>();
            let ipport = net::SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), port);
            let contact = Contact{
                endpoint: Endpoint::Tcp(SocketAddr::V4(ipport)),
                last_updated: Timestamp{ timestamp: time::now_utc() }
            };
            contacts.push(contact);
        }

        let file_name = BootstrapHandler::get_file_name();
        let path = Path::new(&file_name);
        let mut bootstrap_handler = BootstrapHandler::new();
        let file = fs::File::create(&path);

        // check that the file got created...
        assert!(file.is_ok());

        // insert contacts...
        assert!(bootstrap_handler.insert_contacts(contacts.clone()).is_ok());
        let bootstrap: Bootstrap = bootstrap_handler.read_bootstrap_file().unwrap();
        let recovered_contacts : Contacts = bootstrap.contacts;
        // sort contacts w.r.t increasing last updated times...
        let sorted_contacts = contacts
            .into_iter()
            .sort_by(|a, b| Ord::cmp(&b.last_updated.timestamp, &a.last_updated.timestamp))
            .into_iter()
            .map(|contact| contact)
            .collect::<Vec<Contact>>();

        // check that the recovered contacts are the same as the originals...
        assert_eq!(recovered_contacts, sorted_contacts);
        // check the number of contacts is MAX_CONTACTS...
        assert_eq!(recovered_contacts.len(), MAX_CONTACTS);

        // get the last contact in the list and update it...
        let mut updated_contact = recovered_contacts[recovered_contacts.len() - 1].clone();
        let mut updated_contacts = Vec::new();

        updated_contact.last_updated.timestamp = time::now_utc();
        updated_contacts.push(updated_contact.clone());

        // insert the updated contact...
        assert!(bootstrap_handler.insert_contacts(updated_contacts.clone()).is_ok());
        let bootstrap: Bootstrap = bootstrap_handler.read_bootstrap_file().unwrap();
        let recovered_contacts : Contacts = bootstrap.contacts;

        // check that the recovered contacts are not the same as the originals...
        assert!(recovered_contacts != sorted_contacts);
        // check the number of contacts is still MAX_CONTACTS...
        assert_eq!(recovered_contacts.len(), MAX_CONTACTS);
        // check that the updated contact is not still at the end of the list...
        let last_contact = recovered_contacts[recovered_contacts.len() - 1].clone();
        assert!(last_contact != updated_contact.clone());
        // check that the updated contact is at the start of the list...
        let first_contact = recovered_contacts[0].clone();
        assert_eq!(first_contact, updated_contact.clone());

        // remove the bootstrap file from disk...
        match fs::remove_file(file_name.clone()) {
            Ok(_) => (),
            Err(e) => println!("Failed to remove {}: {}", file_name, e),
        };
    }
}
