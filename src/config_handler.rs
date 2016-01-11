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
//! This means that `read_config_file()`, `create_default_config_file()`, and
//! `write_config_file()` should not be called concurrently with one another.

use error::Error;
use endpoint::Endpoint;
use file_handler::FileHandler;

#[derive(PartialEq, Eq, Debug, RustcDecodable, RustcEncodable, Clone)]
pub struct Config {
    pub hard_coded_contacts: Vec<Endpoint>,
}

impl Config {
    pub fn make_default() -> Config {
        Config { hard_coded_contacts: vec![] /* No hardcoded endpoints */ }
    }
}

pub fn read_config_file() -> Result<Config, ::error::Error> {
    let mut file_handler = FileHandler::new(try!(get_file_name()));
    Ok(try!(file_handler.read_file::<Config>()))
}

// This is a best-effort to create a config file - we don't care about the result.
pub fn create_default_config_file() -> Result<(), Error> {
    let mut file_handler = FileHandler::new(try!(get_file_name()));
    Ok(try!(file_handler.write_file(&Config::make_default())))
}

/// Writes a Crust config file **for use by tests and examples**.
///
/// The file is written to the [`current_bin_dir()`](file_handler/fn.current_bin_dir.html)
/// with the appropriate file name.
///
/// N.B. This method should only be used as a utility for test and examples.  In normal use cases,
/// this file should be created by the installer for the dependent application.
pub fn write_config_file(hard_coded_endpoints: Option<Vec<Endpoint>>)
                         -> Result<::std::path::PathBuf, ::error::Error> {
    use std::io::Write;

    let default = Config::make_default();

    let config = Config {
        hard_coded_contacts: hard_coded_endpoints.unwrap_or(default.hard_coded_contacts),
    };
    let mut config_path = try!(::file_handler::current_bin_dir());
    config_path.push(try!(get_file_name()));
    let mut file = try!(::std::fs::File::create(&config_path));
    try!(write!(&mut file,
                "{}",
                ::rustc_serialize::json::as_pretty_json(&config)));
    try!(file.sync_all());
    Ok(config_path)
}

fn get_file_name() -> Result<::std::path::PathBuf, Error> {
    let mut name = try!(::file_handler::exe_file_stem());
    name.set_extension("crust.config");
    Ok(name)
}

#[cfg(test)]
mod test {
    #[test]
    fn read_config_file_test() {
        let mut hard_coded_endpoints = Vec::new();
        let mut hard_coded_contacts = Vec::new();
        for _ in 0..10 {
            let random_contact = ::util::random_endpoint();
            hard_coded_endpoints.push(random_contact.clone());
            hard_coded_contacts.push(random_contact);
        }
        let config = super::Config { hard_coded_contacts: hard_coded_contacts };
        let path_buf = unwrap_result!(super::write_config_file(Some(hard_coded_endpoints)));
        match super::read_config_file() {
            Ok(recovered_config) => assert_eq!(config, recovered_config),
            Err(_) => panic!("Failed to read config file."),
        }

        // Clean up
        match ::file_handler::current_bin_dir() {
            Ok(mut config_path) => {
                config_path.push(path_buf);
                let _ = ::std::fs::remove_file(&config_path);
            }
            Err(_) => (),
        };
    }

    #[test]
    fn parse_sample_config_file() {
        use std::path::Path;
        use std::io::Read;
        use super::Config;
        use rustc_serialize::json;

        let path = Path::new("installer/sample.config").to_path_buf();

        let mut file = match ::std::fs::File::open(path) {
            Ok(file) => file,
            Err(what) => {
                panic!(format!("Error opening sample.config: {:?}", what));
            }
        };

        let mut encoded_contents = String::new();

        if let Err(what) = file.read_to_string(&mut encoded_contents) {
            panic!(format!("Error reading sample.config: {:?}", what));
        }

        if let Err(what) = json::decode::<Config>(&encoded_contents) {
            panic!(format!("Error parsing sample.config: {:?}", what));
        }
    }
}
