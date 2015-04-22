// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe Software.

use time;
use cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide::crypto;
use transport::Endpoint;
use std::fs::File;
use std::io::prelude::*;
use std::path;
use std::env;

pub type BootStrapContacts = Vec<Contact>;

static MAX_LIST_SIZE: usize = 1500;

macro_rules! convert_to_array {
    ($container:ident, $size:expr) => {{
        if $container.len() != $size {
            None
        } else {
            use std::mem;
            let mut arr : [_; $size] = unsafe { mem::uninitialized() };
            for element in $container.into_iter().enumerate() {
                let old_val = mem::replace(&mut arr[element.0], element.1);
                unsafe { mem::forget(old_val) };
            }
            Some(arr)
        }
    }};
}

// TODO Move Contact to maidsafe_types
pub struct Contact {
    endpoint: Endpoint,
    public_key: crypto::asymmetricbox::PublicKey,
}

impl Contact {
    pub fn new(endpoint: Endpoint, public_key: crypto::asymmetricbox::PublicKey) -> Contact {
        Contact {
            endpoint: endpoint,
            public_key: public_key
        }
    }
}

impl Encodable for Contact {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let crypto::asymmetricbox::PublicKey(ref public_key) = self.public_key;
        CborTagEncode::new(5483_000, &(&self.endpoint, public_key.as_ref())).encode(e)
    }
}

impl Decodable for Contact {
    fn decode<D: Decoder>(d: &mut D)->Result<Contact, D::Error> {
        try!(d.read_u64());
        let (endpoint, public_key) : (Endpoint, Vec<u8>) = try!(Decodable::decode(d));
        let public_key = convert_to_array!(public_key, crypto::asymmetricbox::PUBLICKEYBYTES);

        if public_key.is_none() {
            return Err(d.error("PublicKey size"));
        }

        let public_key = crypto::asymmetricbox::PublicKey(public_key.unwrap());
        Ok(Contact::new(endpoint, public_key))
    }
}

impl Clone for Contact {
    fn clone(&self) -> Contact {
        Contact {
            endpoint: self.endpoint.clone(),
            public_key: self.public_key.clone(),
        }
    }
}

pub struct BootStrapHandler {
    file_name: String,
    last_updated: time::Tm,
}

impl BootStrapHandler {
    pub fn new() -> BootStrapHandler {
        let app_path = match env::current_exe() {
                            Ok(exe_path) => exe_path,
                            Err(e) => panic!("Failed to get current exe path: {}", e),
                       };
        let app_with_extension = app_path.file_name().unwrap();
        let app_name = path::Path::new(app_with_extension).file_stem().unwrap();

        let mut filename = String::new();
        filename.push_str("./");
        filename.push_str(app_name.to_str().unwrap());
        filename.push_str(".bootstrap.cache");

        let bootstrap = BootStrapHandler {
            file_name: filename,
            last_updated: time::now(),
        };
        bootstrap
    }

    pub fn get_max_list_size() -> usize {
        MAX_LIST_SIZE
    }

    pub fn get_update_duration() -> time::Duration {
        time::Duration::hours(4)
    }

    pub fn add_bootstrap_contacts(&mut self, contacts: BootStrapContacts) {
        self.insert_bootstrap_contacts(contacts);
        if time::now() > self.last_updated + BootStrapHandler::get_update_duration() {
            self.check_bootstrap_contacts();
        }
    }

    pub fn read_bootstrap_contacts(&self) -> BootStrapContacts {
        let mut file = File::open(&self.file_name).unwrap();
        let mut content = String::new();

		file.read_to_string(&mut content);

		let mut decoder = cbor::Decoder::from_bytes(content.as_bytes());
		let contacts: BootStrapContacts = decoder.decode().next().unwrap().unwrap();
        contacts
    }

    pub fn replace_bootstrap_contacts(&mut self, contacts: BootStrapContacts) {
        self.remove_bootstrap_contacts();
        self.insert_bootstrap_contacts(contacts);
    }

    pub fn out_of_date(&self) -> bool {
        time::now() > self.last_updated + BootStrapHandler::get_update_duration()
    }

    pub fn reset_timer(&mut self) {
        self.last_updated = time::now();
    }

    fn insert_bootstrap_contacts(&mut self, contacts: BootStrapContacts) {
    	if !contacts.is_empty() {
	        let mut open_file = File::open(&self.file_name).unwrap();
	        let mut content = String::new();

			open_file.read_to_string(&mut content);

			let mut decoder = cbor::Decoder::from_bytes(content.as_bytes());
            let mut current_contacts: BootStrapContacts = decoder.decode().next().unwrap().unwrap();

            for i in 0..contacts.len() {
	           current_contacts.push(contacts[i].clone());
            }
	        let mut e = cbor::Encoder::from_memory();
			e.encode(&[current_contacts]).unwrap();
			let mut create_file = File::create(&self.file_name).unwrap();
			create_file.write_all(&e.into_bytes());
        }
    }

    fn remove_bootstrap_contacts(&mut self) {
 		File::create(&self.file_name);
    }

    fn check_bootstrap_contacts(&self) {
        ;
    }
}

#[cfg(test)]
mod test {
    use bootstrap::{Contact, BootStrapHandler};
    use std::net;
    use sodiumoxide;
    use cbor;
    use maidsafe_types;
    use rand;

    #[test]
    fn serialisation_contact() {
        let name_type = maidsafe_types::NameType([3u8; 64]);
        let addr_1 = net::SocketAddrV4::new(net::Ipv4Addr::new(1,2,3,4), 8080);
        let addr_2 = net::SocketAddrV4::new(net::Ipv4Addr::new(1,2,3,4), 9080);
        let pub_key = sodiumoxide::crypto::asymmetricbox::PublicKey([20u8;32]);
        let contact_before = Contact::new(name_type, (addr_1, addr_2), pub_key);

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&contact_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let contact_after: Contact = d.decode().next().unwrap().unwrap();
        assert!(contact_before.id == contact_after.id);
    }

    #[test]
    fn bootstrap_crud_test() {
        use std::fs::File;
        use std::path::Path;

        let mut contacts = Vec::new();
        for i in 0..10 {
            let random_id = [rand::random::<u8>(); 64];
            let random_addr_0 = [rand::random::<u8>(); 4];
            let random_addr_1 = [rand::random::<u8>(); 4];
            let port_0: u8 = rand::random::<u8>();
            let port_1: u8 = rand::random::<u8>();
            let addr_0 = net::SocketAddrV4::new(net::Ipv4Addr::new(random_addr_0[0], random_addr_0[1], random_addr_0[2], random_addr_0[3]), port_0 as u16);
            let addr_1 = net::SocketAddrV4::new(net::Ipv4Addr::new(random_addr_1[0], random_addr_1[1], random_addr_1[2], random_addr_1[3]), port_1 as u16);
            let (public_key, _) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
            let new_contact = Contact::new(maidsafe_types::NameType::new(random_id), (addr_0, addr_1), public_key);
            contacts.push(new_contact);
        }

        let contacts_clone = contacts.clone();
        let path = Path::new("./bootstrap.cache");

        let mut bootstrap_handler = BootStrapHandler::new();
        let file = File::open(&path);
        file.unwrap(); // Check whether the database file is created
        // Add Contacts
        bootstrap_handler.add_bootstrap_contacts(contacts);
        // Read Contacts
        let mut read_contact = bootstrap_handler.read_bootstrap_contacts();
        assert!(read_contact.len() == 10);
        let empty_contact: Vec<Contact> = Vec::new();
        // Replace Contacts
        bootstrap_handler.replace_bootstrap_contacts(empty_contact);
        assert_eq!(contacts_clone.len(), read_contact.len());
        // Assert Replace
        read_contact = bootstrap_handler.read_bootstrap_contacts();
        assert!(read_contact.len() == 0);
    }

}
