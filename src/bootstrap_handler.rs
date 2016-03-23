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

use std::ffi::OsString;

use error::Error;
use static_contact_info::StaticContactInfo;
use config_file_handler::FileHandler;
use config_file_handler;

const ENABLE_BOOTSTRAP_CACHE: bool = false;

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
        if ENABLE_BOOTSTRAP_CACHE {
            try!(self.insert_contacts(contacts, prune));
            // TODO(Team) this implementation is missing and should be considered in next planning
            if ::time::now() > self.last_updated + Self::duration_between_updates() {
                // self.check_bootstrap_contacts();
            }
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
    // TODO(canndrew): Add some unit tests.
}

