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

use std::io;
use std::sync::mpsc;
use std::io::BufReader;
use std::net::TcpStream;
use rustc_serialize::Decodable;
use socket_addr::SocketAddr;
use sodiumoxide::crypto::box_::PublicKey;

const MAX_ALLOWED_TCP_PAYLOAD_SIZE: usize = 1024 * 1024 * 2;

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

pub struct Receiver {
    stream: BufReader<TcpStream>,
}

impl Receiver {
    pub fn tcp(stream: TcpStream) -> Self {
        Receiver { stream: BufReader::new(stream) }
    }


    #[allow(unsafe_code)]
    fn basic_receive<D: Decodable + ::std::fmt::Debug>(&mut self) -> io::Result<D> {
        use std::io::Cursor;
        use bincode::SizeLimit;
        use maidsafe_utilities::serialisation::deserialise_with_limit;
        use byteorder::{ReadBytesExt, LittleEndian};

        let mut payload_size_buffer = [0u8; 4];
        try!(self.fill_buffer(&mut payload_size_buffer[..]));
        let payload_size =
            try!(Cursor::new(&payload_size_buffer[..]).read_u32::<LittleEndian>()) as usize;

        if payload_size > MAX_ALLOWED_TCP_PAYLOAD_SIZE {
            return Err(io::Error::new(io::ErrorKind::Other,
                                      format!("Payload size prohibitive at {} bytes",
                                              payload_size)));
        }

        let mut payload = Vec::with_capacity(payload_size);
        unsafe {
            payload.set_len(payload_size);
        }
        try!(self.fill_buffer(&mut payload));

        let msg = deserialise_with_limit(&mut payload, SizeLimit::Infinite);

        match msg {
            Ok(a) => Ok(a),
            Err(err) => {
                debug!("Deserialisation error: {:?}", err);
                Err(io::Error::new(io::ErrorKind::InvalidData, "Deserialisation failure"))
            }
        }
    }

    fn fill_buffer(&mut self, mut buffer_view: &mut [u8]) -> io::Result<()> {
        use std::io::Read;

        while buffer_view.len() != 0 {
            match self.stream.read(&mut buffer_view) {
                Ok(rxd_bytes) => {
                    if rxd_bytes == 0 {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                                  "Zero byte read - EOF reached, graceful exit."));
                    }

                    let temp_buffer_view = buffer_view;
                    buffer_view = &mut temp_buffer_view[rxd_bytes..];
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => (),
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    pub fn receive(&mut self) -> io::Result<CrustMsg> {
        self.basic_receive::<CrustMsg>()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, RustcEncodable, RustcDecodable)]
pub enum CrustMsg {
    Heartbeat,
    BootstrapRequest(PublicKey, u64),
    BootstrapResponse(PublicKey),
    ExternalEndpointRequest,
    ExternalEndpointResponse(SocketAddr),
    Connect(PublicKey, u64),
    Message(Vec<u8>),
}
