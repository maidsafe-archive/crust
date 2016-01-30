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

use event::WriteEvent;

use cbor;
use std::io;
use std::sync::mpsc;
use std::io::BufReader;
use std::net::TcpStream;
use rustc_serialize::Decodable;
use utp_connections::UtpWrapper;
use maidsafe_utilities::serialisation::serialise;

pub struct RaiiSender(pub mpsc::Sender<WriteEvent>);

impl RaiiSender {
    fn send_bytes(&self, bytes: Vec<u8>) -> io::Result<()> {
        self.0
            .send(WriteEvent::Write(bytes))
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "can't send"))
    }

    pub fn send(&self, msg: &[u8]) -> io::Result<()> {
        let crust_msg = CrustMsg { raw_data: msg.to_owned() };
        self.send_bytes(unwrap_result!(serialise(&crust_msg)))
    }
}

impl Drop for RaiiSender {
    fn drop(&mut self) {
        let _ = self.0
                    .send(WriteEvent::Shutdown)
                    .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "can't send"));
    }
}

#[allow(variant_size_differences)]
pub enum Receiver {
    Tcp(cbor::Decoder<BufReader<TcpStream>>),
    Utp(cbor::Decoder<BufReader<UtpWrapper>>),
}

impl Receiver {
    fn basic_receive<D: Decodable + ::std::fmt::Debug>(&mut self) -> io::Result<D> {
        let msg = match *self {
            Receiver::Tcp(ref mut decoder) => decoder.decode::<D>().next(),
            Receiver::Utp(ref mut decoder) => decoder.decode::<D>().next(),
        };
        match msg {
            Some(a) => {
                a.or(Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to decode CBOR")))
            }
            None => {
                Err(io::Error::new(io::ErrorKind::NotConnected, "Decoder reached end of stream"))
            }
        }
    }

    pub fn receive(&mut self) -> io::Result<Vec<u8>> {
        Ok(try!(self.basic_receive::<CrustMsg>()).raw_data)
    }
}

#[derive(Debug, RustcEncodable, RustcDecodable)]
struct CrustMsg {
    raw_data: Vec<u8>,
}
