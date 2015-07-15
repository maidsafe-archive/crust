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
use transport::{Endpoint, Port};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::env;
use rustc_serialize::json;
use std::io;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Timestamp {
    pub timestamp: time::Tm,
}

impl Timestamp {

    /// Construct a Timestamp with current UTC time.
    pub fn new() -> Timestamp {
        Timestamp { timestamp: time::now_utc() }
    }
}

impl Encodable for Timestamp {
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        e.emit_seq(11usize, |encoder| {
            try!(encoder.emit_seq_elt(00usize, |encoder| self.timestamp.tm_sec.encode(encoder)));
            try!(encoder.emit_seq_elt(01usize, |encoder| self.timestamp.tm_min.encode(encoder)));
            try!(encoder.emit_seq_elt(02usize, |encoder| self.timestamp.tm_hour.encode(encoder)));
            try!(encoder.emit_seq_elt(03usize, |encoder| self.timestamp.tm_mday.encode(encoder)));
            try!(encoder.emit_seq_elt(04usize, |encoder| self.timestamp.tm_mon.encode(encoder)));
            try!(encoder.emit_seq_elt(05usize, |encoder| self.timestamp.tm_year.encode(encoder)));
            try!(encoder.emit_seq_elt(06usize, |encoder| self.timestamp.tm_wday.encode(encoder)));
            try!(encoder.emit_seq_elt(07usize, |encoder| self.timestamp.tm_yday.encode(encoder)));
            try!(encoder.emit_seq_elt(08usize, |encoder| self.timestamp.tm_isdst.encode(encoder)));
            try!(encoder.emit_seq_elt(09usize, |encoder| self.timestamp.tm_utcoff.encode(encoder)));
            try!(encoder.emit_seq_elt(10usize, |encoder| self.timestamp.tm_nsec.encode(encoder)));

            Ok(())
        })
    }
}

impl Decodable for Timestamp {
    fn decode<D: Decoder>(d: &mut D) -> Result<Timestamp, D::Error> {
        let (sec, min, hour, mday, mon, year, wday, yday, isdst, utcoff, nsec):
            (i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32) = try!(Decodable::decode(d));

        let timestamp = time::Tm {
            tm_sec    : sec,
            tm_min    : min,
            tm_hour   : hour,
            tm_mday   : mday,
            tm_mon    : mon,
            tm_year   : year,
            tm_wday   : wday,
            tm_yday   : yday,
            tm_isdst  : isdst,
            tm_utcoff : utcoff,
            tm_nsec   : nsec
        };

        Ok(Timestamp { timestamp: timestamp })
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, RustcDecodable, RustcEncodable)]
pub struct Contact {
    pub endpoint: Endpoint,
    pub last_updated: Timestamp,
}

pub type Contacts = Vec<Contact>;


#[derive(PartialEq, Debug, RustcDecodable, RustcEncodable)]
pub struct Config {
    pub preferred_ports: Vec<Port>,
    pub hard_coded_contacts: Contacts,
    pub beacon_port: u16,
}

pub fn default_config_path() -> io::Result<(PathBuf)> {
    let current_exe_path = try!(env::current_exe());
    let exe_name = try!(current_exe_path.file_name()
        .ok_or_else(||io::Error::new(io::ErrorKind::Other, format!("Failed to read current exe file name"))));
    let mut config_name: PathBuf = PathBuf::from(exe_name.to_os_string());;
    config_name.set_extension("config");
    let mut current_dir = try!(env::current_dir());
    current_dir.push(config_name);
    Ok(current_dir)
}

pub fn read_file(file_name : &PathBuf) -> io::Result<(Config)> {
    let mut file = try!(File::open(file_name));
    let mut contents = String::new();
    let _ = try!(file.read_to_string(&mut contents));
    json::decode(&contents)
         .map_err(|error| io::Error::new(io::ErrorKind::Other,
                                         format!("Failed to decode config file: {}", error)))
}

pub fn write_file(file_name : &PathBuf, config: &Config) -> io::Result<()> {
    let mut file = try!(File::create(file_name));
    try!(write!(&mut file, "{}", json::as_pretty_json(&config)));
    file.sync_all()
}

/// Writes config file and parametes to user specified or default location
pub fn write_config_file(file_path : Option<PathBuf>,
                         preferred_ports: Option<Vec<Port>>,
                         hard_coded_endpoints: Option<Vec<Endpoint>>,
                         beacon_port: Option<u16>) -> io::Result<(PathBuf)> {
    let mut hard_coded_contacts: Contacts = vec![];
    match hard_coded_endpoints {
        Some(endpoints) => {
            for endpoint in endpoints {
                hard_coded_contacts.push(Contact{endpoint: endpoint, last_updated: Timestamp::new()});
            }
        },
        None => {}
    };

    let config = Config{ preferred_ports: preferred_ports.unwrap_or(vec![Port::Tcp(0u16), Port::Utp(0u16)]),
                         hard_coded_contacts: hard_coded_contacts,
                         beacon_port: beacon_port.unwrap_or(0u16),
                       };

    let config_path = match file_path{
        Some(path)=> { path},
        None => {
            try!(default_config_path())
        }
    };

    try!(write_file(&config_path, &config));
    Ok(config_path)
}


#[cfg(test)]
mod test {
    use super::*;
    use std::net;
    use std::net::SocketAddr;
    use transport::{Endpoint, Port};
    use std::fs;
    use rand;

    #[test]
    fn read_config_file_test() {
        let mut hard_coded_contacts = Vec::new();
        for _ in 0..10 {
            let mut random_addr_0 = Vec::with_capacity(4);
            random_addr_0.push(rand::random::<u8>());  // TODO move to utility
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());
            random_addr_0.push(rand::random::<u8>());

            let port_0: u16 = rand::random::<u16>();
            let addr_0 = net::SocketAddrV4::new(net::Ipv4Addr::new(random_addr_0[0],
                random_addr_0[1], random_addr_0[2], random_addr_0[3]), port_0);
            let new_contact = Contact {
                endpoint: Endpoint::Tcp(SocketAddr::V4(addr_0)),
                last_updated: Timestamp::new()
            };
            hard_coded_contacts.push(new_contact);
        }
        let config = Config{ preferred_ports: vec![Port::Tcp(rand::random::<u16>())],
                             hard_coded_contacts: hard_coded_contacts,
                             beacon_port: rand::random::<u16>(),
                           };

        let file_name = default_config_path().unwrap();
        assert_eq!(write_file(&file_name, &config).ok(), Some(()));
        assert_eq!(read_file(&file_name).ok(), Some(config));
        let _  = fs::remove_file(&file_name);
    }
}
