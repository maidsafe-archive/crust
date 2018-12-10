// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use common::PeerInfo;
use config_file_handler::{self, FileHandler};
use std::ffi::OsString;

const _ENABLE_BOOTSTRAP_CACHE: bool = false;
const _MAX_BOOTSTRAP_CACHE_CONTACTS: usize = 1500;

pub struct Cache {
    file_handler: FileHandler<Vec<PeerInfo>>,
}

impl Cache {
    pub fn _cleanup() -> ::Res<()> {
        config_file_handler::cleanup(&Self::get_default_file_name()?)?;
        Ok(())
    }

    pub fn new(name: &Option<String>) -> ::Res<Self> {
        let name = if let Some(name) = name.clone() {
            OsString::from(name)
        } else {
            Self::get_default_file_name()?
        };

        Ok(Cache {
            file_handler: FileHandler::new(&name, true)?, // last_updated: Instant::now(),
        })
    }

    pub fn get_default_file_name() -> ::Res<OsString> {
        let mut name = config_file_handler::exe_file_stem()?;
        name.push(".bootstrap.cache");
        Ok(name)
    }

    // pub fn update_contacts(&mut self,
    //                        contacts: Vec<StaticContactInfo>,
    //                        prune: Vec<StaticContactInfo>)
    //                        -> ::Res<()> {
    //     if ENABLE_BOOTSTRAP_CACHE {
    //         try!(self.insert_contacts(contacts, prune));
    //         // TODO(Team) this implementation is missing and should be considered in next
    //         // planning
    //         if Instant::now() > self.last_updated + Self::duration_between_updates() {
    //             // self.check_bootstrap_contacts();
    //         }
    //     }

    //     Ok(())
    // }

    pub fn read_file(&mut self) -> Vec<PeerInfo> {
        self.file_handler.read_file().ok().unwrap_or_else(|| vec![])
    }

    pub fn remove_peer_acceptor(&mut self, _peer: PeerInfo) {}

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
