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
use std::net;
use transport::Endpoint;
use std::fs::File;
use std::env;

type BootStrapContacts = Vec<Contact>;

static MAX_LIST_SIZE: usize = 1500;

fn array_to_vec(arr: &[u8]) -> Vec<u8> {
    let mut vector = Vec::new();
    for i in arr.iter() {
        vector.push(*i);
    }
    vector
}

fn vector_as_u8_4_array(vector: Vec<u8>) -> [u8;4] {
    let mut arr = [0u8;4];
    for i in (0..4) {
        arr[i] = vector[i];
    }
    arr
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
    	let ep = std::to_string::<SocketAddr>(self.endpoint).unwrap();
        // let addr_ip = array_to_vec(&self.endpoint.ip().octets());
        // let addr_port = &self.endpoint.port();
        let public_key = array_to_vec(&self.public_key.0);
        CborTagEncode::new(5483_000, &(ep, public_key)).encode(e)
    }
}

impl Decodable for Contact {
    fn decode<D: Decoder>(d: &mut D)->Result<Contact, D::Error> {
        try!(d.read_u64());

        let (endpoint, public_key) = try!(Decodable::decode(d));
        
        // let addr_ip: [u8;4] = vector_as_u8_4_array(addr_ip_);
        // let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(addr_ip, addr_port));
        let pub_key = crypto::asymmetricbox::PublicKey(array_to_vec(public_key));

        Ok(Contact::new(endpoint, pub_key))
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
    	let mut app_name = try!(env::current_exe().file_name().file_stem());
        let mut bootstrap = BootStrapHandler {
            file_name: String::new("./" + app_name + ".bootstrap.cache"),
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
        let mut file = try!(File::open(self.file_name));
        let mut content = String::new();

		try!(file.read_to_string(&mut content));

		let mut decoder = cbor::Decoder::from_bytes(content.unwrap());
		contacts = try!(decoder.decode().next().unwrap().unwrap());
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
        	let mut current_contacts = BootStrapContacts::new();
	        let mut open_file = try!(File::open(self.file_name));
	        let mut content = String::new();

			try!(open_file.read_to_string(&mut content));

			let mut decoder = cbor::Decoder::from_bytes(content.unwrap());
			current_contacts = try!(decoder.decode().next().unwrap().unwrap());
	        current_contacts.push_all(contacts);

	        let mut e = cbor::Encoder::from_memory();
			e.encode(&[current_contacts]).unwrap();
			let mut create_file = try!(File::create(self.file_name));
			try!(create_file.write_all(e.into_bytes()));
        }
    }

    fn remove_bootstrap_contacts(&mut self) {
 		try!(File::create(self.file_name));
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
