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

//! For notes on thread- and process-safety of `FileHandler`, please see the docs either in
//! file_handler.rs or at
//! http://maidsafe.net/crust/master/crust/file_handler/struct.FileHandler.html#thread--and-process-safety
//!
//! This means that none of the public functions of `BootstrapHandler` should be called concurrently
//! with any other one.

use transport::Endpoint;
use file_handler::FileHandler;
use std::io;
use std::net::SocketAddr;

pub struct BootstrapHandler {
    file_handler: FileHandler,
    last_updated: ::time::Tm,
}

impl BootstrapHandler {
    #[allow(dead_code)]
    pub fn cleanup() -> io::Result<()> {
        FileHandler::cleanup(&get_file_name())
    }

    pub fn new() -> BootstrapHandler {
        BootstrapHandler {
            file_handler: FileHandler::new(get_file_name()),
            last_updated: ::time::now(),
        }
    }

    pub fn update_contacts(&mut self, contacts: Vec<Endpoint>,
                           prune: Vec<Endpoint>) -> Result<(), ::error::Error> {
        try!(self.insert_contacts(contacts, prune));
        // TODO(Team) this implementation is missing and should be considered in next planning
        if ::time::now() > self.last_updated + Self::duration_between_updates() {
            // self.check_bootstrap_contacts();
        }
        Ok(())
    }

    pub fn read_file(&mut self) -> Result<Vec<Endpoint>, ::error::Error> {
        self.file_handler.read_file::<Vec<Endpoint>>()
    }

    fn duration_between_updates() -> ::time::Duration {
        ::time::Duration::hours(4)
    }

    fn max_contacts() -> usize {
        1500
    }

    fn insert_contacts(&mut self, mut contacts: Vec<Endpoint>,
                                  prune: Vec<Endpoint>)
            -> Result<(), ::error::Error> {
        let mut bootstrap_contacts = self.read_file().unwrap_or_else(|e| {
            debug!("Error reading Bootstrap file: {:?}.", e);
            Vec::new()
        });

        // We wouldn't add any loopback addresses nor addresses from our local
        // LAN to the bootstrap cache. We can always find such addresses using
        // beacon and more often than not they would be obsolete very soon.
        contacts.retain(|contact| match contact.get_address() {
            SocketAddr::V4(a) => a.ip().is_global(),
            SocketAddr::V6(a) => a.ip().is_global(),
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

        self.file_handler.write_file(&bootstrap_contacts)
    }
}

fn get_file_name() -> ::std::path::PathBuf {
    let mut name = ::file_handler::exe_file_stem()
                       .unwrap_or(::std::path::Path::new("unknown").to_path_buf());
    name.set_extension("bootstrap.cache");
    name
}

#[cfg(test)]
mod test {
    use transport::Endpoint;

    struct TestFile {
        file_path: ::std::path::PathBuf,
    }

    impl TestFile {
        // This creates an empty bootstrap file in the current bin dir.  This allows the tests to
        // read (and hence write to) this file.  The file is automatically removed when this object
        // is deleted - i.e the file is managed by RAII.
        pub fn new() -> Result<TestFile, ::error::Error> {
            use std::io::Write;
            let mut path = try!(::file_handler::current_bin_dir());
            path.push(super::get_file_name());
            let mut file = try!(::std::fs::File::create(&path));
            let _ = try!(write!(&mut file, "{}",
                ::rustc_serialize::json::as_pretty_json(&Vec::<Endpoint>::new())));
            let _ = try!(file.sync_all());
            Ok(TestFile { file_path: path })
        }

        fn remove_file(&mut self) {
            let _ = ::std::fs::remove_file(&self.file_path);
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            self.remove_file();
        }
    }

    #[test]
    fn duplicates() {
        let number = 10usize;
        let contacts = ::util::random_global_endpoints(number);
        assert_eq!(contacts.len(), number);
        let _test_file = TestFile::new().unwrap();

        // Add contacts
        let mut bootstrap_handler = super::BootstrapHandler::new();
        assert!(bootstrap_handler.update_contacts(contacts.clone(),
                                                  Vec::<Endpoint>::new()).is_ok());

        // Check contacts can be retrieved OK
        assert_eq!(bootstrap_handler.read_file().unwrap(), contacts);

        // Try duplicating each contact
        for i in 0..number {
            let mut duplicate_contacts = Vec::new();
            duplicate_contacts.push(contacts[i].clone());
            assert!(bootstrap_handler.update_contacts(duplicate_contacts,
                                                      Vec::<Endpoint>::new()).is_ok());
        }

        // Bootstrap contacts should remain unaltered
        assert_eq!(bootstrap_handler.read_file().unwrap(), contacts);
    }

    #[test]
    fn prune() {
        let number = 10usize;
        let mut contacts = ::util::random_global_endpoints(number);
        assert_eq!(contacts.len(), number);
        let _test_file = TestFile::new().unwrap();

        // Add contacts
        let mut bootstrap_handler = super::BootstrapHandler::new();
        assert!(bootstrap_handler.update_contacts(contacts.clone(),
                                                  Vec::<Endpoint>::new()).is_ok());
        assert_eq!(bootstrap_handler.read_file().unwrap(), contacts);

        // Prune each contact
        for i in 0..number {
            let mut prune_contacts = Vec::new();
            prune_contacts.push(contacts[i].clone());
            assert!(bootstrap_handler.update_contacts(Vec::<Endpoint>::new(),
                                                      prune_contacts).is_ok());
        }

        // Retrieved contacts should be empty
        assert!(bootstrap_handler.read_file().unwrap().is_empty());

        // Re-add the contacts and check they can be retrieved OK
        assert!(bootstrap_handler.update_contacts(contacts.clone(),
                                                  Vec::<Endpoint>::new()).is_ok());
        let mut retrieved_contacts = bootstrap_handler.read_file().unwrap();
        assert_eq!(retrieved_contacts, contacts);

        // Create a new contact
        let new_contact = ::util::random_global_endpoint();
        let new_contacts = vec![new_contact.clone(); 1];

        // Get the last contact in the list and prune it from the bootstrap file
        let prune_contacts = vec![retrieved_contacts.last().unwrap().clone(); 1];

        // Add the new contact while pruning the last
        assert!(bootstrap_handler.update_contacts(new_contacts, prune_contacts).is_ok());

        // Update the contact list with expected entries and check the retrieved contacts match
        let _ = contacts.remove(number - 1);
        contacts.insert(0usize, new_contact.clone());
        retrieved_contacts = bootstrap_handler.read_file().unwrap();
        assert_eq!(retrieved_contacts, contacts);
    }

    #[test]
    fn max_contacts() {
        let contacts = ::util::random_global_endpoints(super::BootstrapHandler::max_contacts());
        assert_eq!(contacts.len(), super::BootstrapHandler::max_contacts());
        let _test_file = TestFile::new().unwrap();

        // Add contacts
        let mut bootstrap_handler = super::BootstrapHandler::new();
        assert!(bootstrap_handler.update_contacts(contacts.clone(),
                                                  Vec::<Endpoint>::new()).is_ok());
        assert_eq!(bootstrap_handler.read_file().unwrap(), contacts);

        // Create a new contact
        let new_contact = ::util::random_global_endpoint();
        let new_contacts = vec![new_contact.clone(); 1];

        // Try inserting without also pruning - bootstrap contacts should remain unaltered
        assert!(bootstrap_handler.insert_contacts(new_contacts.clone(),
                                                  Vec::<Endpoint>::new()).is_ok());
        assert_eq!(bootstrap_handler.read_file().unwrap(), contacts);

        // Get the last contact in the list and prune it from the bootstrap file
        let mut retrieved_contacts = bootstrap_handler.read_file().unwrap();
        let prune_contacts = vec![retrieved_contacts.last().unwrap().clone(); 1];

        // Add the new contact while pruning the last - bootstrap contacts should now contain the
        // new contact at the start of the list and not contain the pruned one
        assert!(bootstrap_handler.update_contacts(new_contacts, prune_contacts.clone()).is_ok());
        retrieved_contacts = bootstrap_handler.read_file().unwrap();
        assert!(retrieved_contacts != contacts);
        assert_eq!(retrieved_contacts.len(), super::BootstrapHandler::max_contacts());
        assert_eq!(*retrieved_contacts.first().unwrap(), new_contact);
        assert!(*retrieved_contacts.last().unwrap() != prune_contacts[0]);
    }

    #[test]
    fn serialise_and_parse() {
        let contacts = ::util::random_endpoints(5);
        let _test_file = TestFile::new().unwrap();
        let mut bootstrap_handler = super::BootstrapHandler::new();
        assert!(bootstrap_handler.update_contacts(contacts.clone(),
                                                  Vec::<Endpoint>::new()).is_ok());
    }
}
