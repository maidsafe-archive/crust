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
use std::cmp;
use std::fmt;

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

#[derive(Clone)]
pub enum PublicKey {
    Asym(crypto::asymmetricbox::PublicKey),
    Sign(crypto::sign::PublicKey),
}

impl cmp::PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        match *self {
            PublicKey::Asym(key0) => {
                match *other {
                    PublicKey::Asym(key1) => key0.0.iter().zip(key1.0.iter()).all(|a| a.0 == a.1),
                    _ => false,
                }
            },
            PublicKey::Sign(key0) => {
                match *other {
                    PublicKey::Sign(key1) => key0.0.iter().zip(key1.0.iter()).all(|a| a.0 == a.1),
                    _ => false
                }
            },
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PublicKey::Asym(key) => {
                write!(f, "crypto::asymmetricbox::PublicKey {:?}", key.0.to_vec())
            },
            PublicKey::Sign(key) => {
                write!(f, "crypto::sign::PublicKey {:?}", key.0.to_vec())
            },
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct Contact {
    endpoint: Endpoint,
    public_key: PublicKey,
}

impl Contact {
    pub fn new(endpoint: Endpoint, public_key: PublicKey) -> Contact {
        Contact {
            endpoint: endpoint,
            public_key: public_key
        }
    }
}

impl Encodable for Contact {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        match self.public_key {
           PublicKey::Asym(crypto::asymmetricbox::PublicKey(ref public_key)) => CborTagEncode::new(5483_400, &(&self.endpoint, public_key.as_ref())).encode(e),
           PublicKey::Sign(crypto::sign::PublicKey(ref public_key)) => CborTagEncode::new(5483_400, &(&self.endpoint, public_key.as_ref())).encode(e),
        }
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
        Ok(Contact::new(endpoint, PublicKey::Asym(public_key)))
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
    pub fn get_file_name() -> String {
       let path =
            match env::current_exe() {
                Ok(exe_path) => exe_path,
                Err(e) => panic!("Failed to get current exe path: {}", e),
            };
        let name_with_extension =
            match path.file_name() {
                Some(exe_with_extension) => exe_with_extension,
                None => panic!("Unknown filename: {}"),
            };
        let name =
            match path::Path::new(name_with_extension).file_stem() {
                Some(exe_name) => exe_name,
                None => panic!("Unknown extension: {}"),
            };

        let mut filename = String::new();
        filename.push_str("./");
        filename.push_str(name.to_str().unwrap());
        filename.push_str(".bootstrap.cache");
        filename
    }

    pub fn new() -> BootStrapHandler {
        let bootstrap = BootStrapHandler {
            file_name: BootStrapHandler::get_file_name(),
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
        let mut contacts = BootStrapContacts::new();
        match File::open(&self.file_name) {
            Ok(mut file) =>  {
                let mut content = Vec::<u8>::new();

                let size = file.read_to_end(&mut content);

                match size {
                    Ok(s) => {
                        if s != 0 {
                            let mut decoder = cbor::Decoder::from_bytes(&content[..]);
                            contacts = decoder.decode().next().unwrap().unwrap();
                        }
                    },
                    _ => panic!("Failed to read file")
                }
                contacts
            },
            _ => panic!("Could not open file"),
        }
    }

    pub fn get_serialised_bootstrap_contacts(&self) -> Vec<u8> {
        match File::open(&self.file_name) {
            Ok(mut file) =>  {
                let mut content = Vec::<u8>::new();
                let size = file.read_to_end(&mut content);

                match size {
                    Ok(_) => {
                        content
                    },
                    _ => panic!("Failed to read file")

                }
            },
            _ => panic!("Could not open file"),
        }
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
        	let mut current_contacts = BootStrapContacts::new();
            match File::open(&self.file_name) {
                Ok(mut open_file) => {
                    let mut content = Vec::<u8>::new();

                    let size = open_file.read_to_end(&mut content);

                    if size.is_ok() && size.unwrap() != 0 {
                        let mut decoder = cbor::Decoder::from_bytes(&content[..]);
                        current_contacts = decoder.decode().next().unwrap().unwrap();
                    }

                    for i in 0..contacts.len() {
                       current_contacts.push(contacts[i].clone());
                    }
                },
                _ => current_contacts = contacts,
            }

            let mut e = cbor::Encoder::from_memory();
            e.encode(&[current_contacts]).unwrap();
            match File::create(&self.file_name) {
                Ok(mut create_file) => {
                    let result = create_file.write_all(&e.into_bytes());
                    assert!(result.is_ok());
                    let result = create_file.sync_all();
                    assert!(result.is_ok());
                },
                _ => panic!("Could not create file"),
            }
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
    use std::net::SocketAddr;
    use sodiumoxide;
    use cbor;
    use rand;
    use transport;

    #[test]
    fn serialisation() {
        let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(1,2,3,4), 8080);
        let pub_key = super::PublicKey::Asym(sodiumoxide::crypto::asymmetricbox::PublicKey([20u8;32]));
        let contact_before = Contact::new(transport::Endpoint::Tcp(SocketAddr::V4(addr)), pub_key);

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&contact_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let contact_after: Contact = d.decode().next().unwrap().unwrap();
        assert_eq!(contact_before, contact_after);
    }

    #[test]
    fn bootstrap_crud_test() {
        use std::fs::File;
        use std::path::Path;

        let mut contacts = Vec::new();
        for i in 0..10 {
            let mut random_addr_0 = Vec::with_capacity(4);
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());

            let port_0: u8 = rand::random::<u8>();
            let addr_0 = net::SocketAddrV4::new(net::Ipv4Addr::new(random_addr_0[0], random_addr_0[1], random_addr_0[2], random_addr_0[3]), port_0 as u16);
            let (public_key, _) = sodiumoxide::crypto::asymmetricbox::gen_keypair();
            let new_contact = Contact::new(transport::Endpoint::Tcp(SocketAddr::V4(addr_0)), super::PublicKey::Asym(public_key));
            contacts.push(new_contact);
        }

        let contacts_clone = contacts.clone();
        let file_name = super::BootStrapHandler::get_file_name();
        let path = Path::new(&file_name);

        let mut bootstrap_handler = BootStrapHandler::new();
        let file = File::create(&path);
        assert!(file.is_ok()); // Check whether the database file is created
        // Add Contacts
        bootstrap_handler.add_bootstrap_contacts(contacts);
        // Read Contacts
        let mut read_contact = bootstrap_handler.read_bootstrap_contacts();
        assert_eq!(read_contact.len(), 10);
        let empty_contact: Vec<Contact> = Vec::new();
        // Replace Contacts
        bootstrap_handler.replace_bootstrap_contacts(empty_contact);
        assert_eq!(contacts_clone.len(), read_contact.len());
        // Assert Replace
        read_contact = bootstrap_handler.read_bootstrap_contacts();
        assert!(read_contact.len() == 0);
    }
}
