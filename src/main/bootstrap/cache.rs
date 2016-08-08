// Copyright 2016 MaidSafe.net limited.
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

use common;
use config_file_handler::{self, FileHandler};

const _ENABLE_BOOTSTRAP_CACHE: bool = false;
const _MAX_BOOTSTRAP_CACHE_CONTACTS: usize = 1500;

pub struct Cache {
    file_handler: FileHandler<Vec<common::SocketAddr>>,
}

impl Cache {
    pub fn _cleanup() -> ::Res<()> {
        try!(config_file_handler::cleanup(&try!(Self::get_default_file_name())));
        Ok(())
    }

    pub fn new(name: &Option<String>) -> ::Res<Self> {
        let name = if let Some(name) = name.clone() {
            OsString::from(name)
        } else {
            try!(Self::get_default_file_name())
        };

        Ok(Cache {
            file_handler: try!(FileHandler::new(&name, true)),
            // last_updated: Instant::now(),
        })
    }

    pub fn get_default_file_name() -> ::Res<OsString> {
        let mut name = try!(config_file_handler::exe_file_stem());
        name.push(".bootstrap.cache");
        Ok(name)
    }

    // pub fn update_contacts(&mut self,
    //                        contacts: Vec<StaticContactInfo>,
    //                        prune: Vec<StaticContactInfo>)
    //                        -> ::Res<()> {
    //     if ENABLE_BOOTSTRAP_CACHE {
    //         try!(self.insert_contacts(contacts, prune));
    //         // TODO(Team) this implementation is missing and should be considered in next planning
    //         if Instant::now() > self.last_updated + Self::duration_between_updates() {
    //             // self.check_bootstrap_contacts();
    //         }
    //     }

    //     Ok(())
    // }

    pub fn read_file(&mut self) -> Vec<common::SocketAddr> {
        self.file_handler.read_file().ok().unwrap_or_else(|| vec![])
    }

    pub fn remove_peer_acceptor(&mut self, _peer: common::SocketAddr) {}

    // fn duration_between_updates() -> Duration {
    //     Duration::from_secs(4 * 60 * 60)
    // }

    // fn max_contacts() -> usize {
    //     MAX_BOOTSTRAP_CACHE_CONTACTS
    // }

    // fn insert_contacts(&mut self,
    //                    mut contacts: Vec<StaticContactInfo>,
    //                    prune: Vec<StaticContactInfo>)
    //                    -> ::Res<()> {
    //     let mut bootstrap_contacts = self.read_file().unwrap_or_else(|e| {
    //         debug!("CrustError reading bootstrap cache file: {}.", e);
    //         Vec::new()
    //     });

    //     bootstrap_contacts.retain(|contact| !prune.contains(&contact));
    //     contacts.retain(|contact| !bootstrap_contacts.contains(&contact));

    //     if bootstrap_contacts.is_empty() {
    //         bootstrap_contacts = contacts;
    //     } else {
    //         loop {
    //             if bootstrap_contacts.len() < Self::max_contacts() && !contacts.is_empty() {
    //                 bootstrap_contacts.insert(0usize, contacts.remove(0usize));
    //             } else {
    //                 break;
    //             }
    //         }
    //     }

    //     Ok(try!(self.file_handler.write_file(&bootstrap_contacts)))
    // }
}

#[cfg(test)]
mod test {
    // TODO(canndrew): Add some unit tests.
}
