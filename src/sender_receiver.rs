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
use cbor::CborError;
use std::io;
use std::sync::mpsc;
use std::io::BufReader;
use std::net::TcpStream;
use rustc_serialize::Decodable;
use utp_connections::UtpWrapper;
use maidsafe_utilities::serialisation::serialise;
use socket_addr::SocketAddr;
use sodiumoxide::crypto::box_::PublicKey;

pub struct RaiiSender(pub mpsc::Sender<WriteEvent>);

impl RaiiSender {
    pub fn send(&self, msg: CrustMsg) -> io::Result<()> {
        self.0
            .send(WriteEvent::Write(msg))
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "can't send"))
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
        loop {
            let msg = match *self {
                Receiver::Tcp(ref mut decoder) => decoder.decode::<D>().next(),
                Receiver::Utp(ref mut decoder) => decoder.decode::<D>().next(),
            };
            match msg {
                Some(Ok(a)) => return Ok(a),
                Some(Err(CborError::Io(e))) => {
                    return Err(e)
                },
                Some(Err(CborError::Decode(e))) | Some(Err(CborError::AtOffset { kind: e, .. })) => {
                    warn!("Failed to decode CBOR: {}", e);
                },
                Some(Err(CborError::Encode(e))) => panic!("impossible"),
                Some(Err(CborError::UnexpectedEOF)) => {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "Unexpected EOF in stream"))
                },
                None => {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "Decoder reached end of stream"))
                }
            }
        }
    }

    pub fn receive(&mut self) -> io::Result<CrustMsg> {
        self.basic_receive::<CrustMsg>()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, RustcEncodable, RustcDecodable)]
pub enum CrustMsg {
    BootstrapRequest(PublicKey),
    BootstrapResponse(PublicKey),
    ExternalEndpointRequest,
    ExternalEndpointResponse(SocketAddr),
    Connect(PublicKey),
    Message(Vec<u8>), // encrypted data
}

