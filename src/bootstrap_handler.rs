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

use std::ffi::{OsStr, OsString};

use error::Error;
use static_contact_info::StaticContactInfo;
use config_file_handler::FileHandler;
use config_file_handler;

pub struct BootstrapHandler {
    file_handler: FileHandler<Vec<StaticContactInfo>>,
    last_updated: ::time::Tm,
}

impl BootstrapHandler {
    #[allow(dead_code)]
    pub fn cleanup() -> Result<(), Error> {
        try!(config_file_handler::cleanup(&try!(get_default_file_name())));
        Ok(())
    }

    pub fn new(name: &Option<String>) -> Result<Self, ::error::Error> {
        let name = if let Some(name) = name.clone() {
            OsString::from(name)
        } else {
            try!(get_default_file_name())
        };

        Ok(BootstrapHandler {
            file_handler: try!(FileHandler::new(&name)),
            last_updated: ::time::now(),
        })
    }

    pub fn update_contacts(&mut self,
                           contacts: Vec<StaticContactInfo>,
                           prune: Vec<StaticContactInfo>)
                           -> Result<(), Error> {
        try!(self.insert_contacts(contacts, prune));
        // TODO(Team) this implementation is missing and should be considered in next planning
        if ::time::now() > self.last_updated + Self::duration_between_updates() {
            // self.check_bootstrap_contacts();
        }
        Ok(())
    }

    pub fn read_file(&mut self) -> Result<Vec<StaticContactInfo>, Error> {
        Ok(try!(self.file_handler.read_file()))
    }

    fn duration_between_updates() -> ::time::Duration {
        ::time::Duration::hours(4)
    }

    fn max_contacts() -> usize {
        1500
    }

    fn insert_contacts(&mut self,
                       mut contacts: Vec<StaticContactInfo>,
                       prune: Vec<StaticContactInfo>)
                       -> Result<(), Error> {
        let mut bootstrap_contacts = self.read_file().unwrap_or_else(|e| {
            debug!("Error reading Bootstrap file: {:?}.", e);
            Vec::new()
        });

        bootstrap_contacts.retain(|contact| !prune.contains(&contact));
        contacts.retain(|contact| !bootstrap_contacts.contains(&contact));

        if bootstrap_contacts.is_empty() {
            bootstrap_contacts = contacts;
        } else {
            loop {
                if bootstrap_contacts.len() < Self::max_contacts() && !contacts.is_empty() {
                    bootstrap_contacts.insert(0usize, contacts.remove(0usize));
                } else {
                    break;
                }
            }
        }

        Ok(try!(self.file_handler.write_file(&bootstrap_contacts)))
    }
}

pub fn get_default_file_name() -> Result<OsString, Error> {
    let mut name = try!(config_file_handler::exe_file_stem());
    name.push(".bootstrap.cache");
    Ok(name)
}

#[cfg(test)]
mod test {

    // TODO(canndrew): Add these tests back
    // the main thing that has changed is that StaticContactInfo has replaced Endpoint. Probably nothing
    // else has changed.

    // use std::net;
    // use endpoint::{Endpoint, Protocol};
    // use socket_addr::SocketAddr;
    //
    // pub fn random_global_endpoints(count: usize) -> Vec<Endpoint> {
    // let mut contacts = Vec::new();
    // for _ in 0..count {
    // contacts.push(random_global_endpoint());
    // }
    // contacts
    // }
    //
    // pub fn random_endpoints(count: usize) -> Vec<Endpoint> {
    // let mut contacts = Vec::new();
    // for _ in 0..count {
    // contacts.push(::util::random_endpoint());
    // }
    // contacts
    // }
    //
    // pub fn random_global_endpoint() -> Endpoint {
    // TODO - randomise V4/V6 and TCP/UTP
    // let address =
    // ::std::net::SocketAddrV4::new(::std::net::Ipv4Addr::new(173, // ensure is a global addr
    // ::rand::random::<u8>(),
    // ::rand::random::<u8>(),
    // ::rand::random::<u8>()),
    // ::rand::random::<u16>());
    // Endpoint::from_socket_addr(Protocol::Tcp, SocketAddr(net::SocketAddr::V4(address)))
    // }
    //
    // struct TestFile {
    // file_path: ::std::path::PathBuf,
    // }
    //
    // impl TestFile {
    // This creates an empty bootstrap file in the current bin dir.  This allows the tests to
    // read (and hence write to) this file.  The file is automatically removed when this object
    // is deleted - i.e the file is managed by RAII.
    // pub fn new() -> Result<TestFile, ::error::Error> {
    // use std::io::Write;
    // let mut path = try!(::config_file_handler::current_bin_dir());
    // path.push(try!(super::get_file_name()));
    // let mut file = try!(::std::fs::File::create(&path));
    // try!(write!(&mut file,
    // "{}",
    // ::rustc_serialize::json::as_pretty_json(&Vec::<Endpoint>::new())));
    // try!(file.sync_all());
    // Ok(TestFile { file_path: path })
    // }
    //
    // fn remove_file(&mut self) {
    // let _ = ::std::fs::remove_file(&self.file_path);
    // }
    // }
    //
    // impl Drop for TestFile {
    // fn drop(&mut self) {
    // self.remove_file();
    // }
    // }
    //
    // #[test]
    // fn duplicates() {
    // let number = 10usize;
    // let contacts = random_global_endpoints(number);
    // assert_eq!(contacts.len(), number);
    // let _test_file = TestFile::new().unwrap();
    //
    // Add contacts
    // let mut bootstrap_handler = unwrap_result!(super::BootstrapHandler::new());
    // assert!(bootstrap_handler.update_contacts(contacts.clone(), Vec::<Endpoint>::new())
    // .is_ok());
    //
    // Check contacts can be retrieved OK
    // assert_eq!(bootstrap_handler.read_file().unwrap(), contacts);
    //
    // Try duplicating each contact
    // for item in &contacts {
    // let mut duplicate_contacts = Vec::new();
    // duplicate_contacts.push(item.clone());
    // assert!(bootstrap_handler.update_contacts(duplicate_contacts, Vec::<Endpoint>::new())
    // .is_ok());
    // }
    //
    // Bootstrap contacts should remain unaltered
    // assert_eq!(bootstrap_handler.read_file().unwrap(), contacts);
    // }
    //
    // #[test]
    // fn prune() {
    // let number = 10usize;
    // let mut contacts = random_global_endpoints(number);
    // assert_eq!(contacts.len(), number);
    // let _test_file = TestFile::new().unwrap();
    //
    // Add contacts
    // let mut bootstrap_handler = unwrap_result!(super::BootstrapHandler::new());
    // assert!(bootstrap_handler.update_contacts(contacts.clone(), Vec::<Endpoint>::new())
    // .is_ok());
    // assert_eq!(bootstrap_handler.read_file().unwrap(), contacts);
    //
    // Prune each contact
    // for item in &contacts {
    // let mut prune_contacts = Vec::new();
    // prune_contacts.push(item.clone());
    // assert!(bootstrap_handler.update_contacts(Vec::<Endpoint>::new(), prune_contacts)
    // .is_ok());
    // }
    //
    // Retrieved contacts should be empty
    // assert!(bootstrap_handler.read_file().unwrap().is_empty());
    //
    // Re-add the contacts and check they can be retrieved OK
    // assert!(bootstrap_handler.update_contacts(contacts.clone(), Vec::<Endpoint>::new())
    // .is_ok());
    // let mut retrieved_contacts = bootstrap_handler.read_file().unwrap();
    // assert_eq!(retrieved_contacts, contacts);
    //
    // Create a new contact
    // let new_contact = random_global_endpoint();
    // let new_contacts = vec![new_contact.clone(); 1];
    //
    // Get the last contact in the list and prune it from the bootstrap file
    // let prune_contacts = vec![retrieved_contacts.last().unwrap().clone(); 1];
    //
    // Add the new contact while pruning the last
    // assert!(bootstrap_handler.update_contacts(new_contacts, prune_contacts).is_ok());
    //
    // Update the contact list with expected entries and check the retrieved contacts match
    // let _ = contacts.remove(number - 1);
    // contacts.insert(0usize, new_contact.clone());
    // retrieved_contacts = bootstrap_handler.read_file().unwrap();
    // assert_eq!(retrieved_contacts, contacts);
    // }
    //
    // #[test]
    // fn max_contacts() {
    // let contacts = random_global_endpoints(super::BootstrapHandler::max_contacts());
    // assert_eq!(contacts.len(), super::BootstrapHandler::max_contacts());
    // let _test_file = TestFile::new().unwrap();
    //
    // Add contacts
    // let mut bootstrap_handler = unwrap_result!(super::BootstrapHandler::new());
    // assert!(bootstrap_handler.update_contacts(contacts.clone(), Vec::<Endpoint>::new())
    // .is_ok());
    // assert_eq!(bootstrap_handler.read_file().unwrap(), contacts);
    //
    // Create a new contact
    // let new_contact = random_global_endpoint();
    // let new_contacts = vec![new_contact.clone(); 1];
    //
    // Try inserting without also pruning - bootstrap contacts should remain unaltered
    // assert!(bootstrap_handler.insert_contacts(new_contacts.clone(), Vec::<Endpoint>::new())
    // .is_ok());
    // assert_eq!(bootstrap_handler.read_file().unwrap(), contacts);
    //
    // Get the last contact in the list and prune it from the bootstrap file
    // let mut retrieved_contacts = bootstrap_handler.read_file().unwrap();
    // let prune_contacts = vec![retrieved_contacts.last().unwrap().clone(); 1];
    //
    // Add the new contact while pruning the last - bootstrap contacts should now contain the
    // new contact at the start of the list and not contain the pruned one
    // assert!(bootstrap_handler.update_contacts(new_contacts, prune_contacts.clone()).is_ok());
    // retrieved_contacts = bootstrap_handler.read_file().unwrap();
    // assert!(retrieved_contacts != contacts);
    // assert_eq!(retrieved_contacts.len(),
    // super::BootstrapHandler::max_contacts());
    // assert_eq!(*retrieved_contacts.first().unwrap(), new_contact);
    // assert!(*retrieved_contacts.last().unwrap() != prune_contacts[0]);
    // }
    //
    // #[test]
    // fn serialise_and_parse() {
    // let contacts = random_endpoints(5);
    // let _test_file = TestFile::new().unwrap();
    // let mut bootstrap_handler = unwrap_result!(super::BootstrapHandler::new());
    // assert!(bootstrap_handler.update_contacts(contacts.clone(), Vec::<Endpoint>::new())
    // .is_ok());
    // }
    //
}
