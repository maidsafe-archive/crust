// Copyright 2015 MaidSafe.net limited
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, versicant_sendon 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

use std::net::{SocketAddr, TcpStream, TcpListener};
use tcp_connections;
use std::io;
use std::io::Result as IoResult;
use std::error::Error;
use std::sync::mpsc;
use beacon;
use cbor;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

pub type Bytes = Vec<u8>;

fn array_to_vec(arr: &[u8]) -> Vec<u8> {
    let mut vector = Vec::new();
    for i in arr.iter() {
        vector.push(*i);
    }
    vector
}

/// Enum representing endpoint of supported protocols
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Endpoint {
    Tcp(SocketAddr),
}

impl Endpoint {
    /// Returns SocketAddr.
    pub fn get_address(&self) -> SocketAddr {
        match *self {
            Endpoint::Tcp(address) => address,
            _ => panic!("No address.")
        }
    }
}

impl Encodable for Endpoint {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let address = array_to_vec(&beacon::serialise_address(self.get_address()));
        CborTagEncode::new(5483_000, &address).encode(e)
    }
}

impl Decodable for Endpoint {
    fn decode<D: Decoder>(d: &mut D)->Result<Endpoint, D::Error> {
        try!(d.read_u64());
        let decoded: Vec<u8> = try!(Decodable::decode(d));
        let address: SocketAddr = beacon::parse_address(&decoded).unwrap();

        Ok(Endpoint::Tcp(address))
    }
}

#[derive(Debug, Clone)]
pub enum Port {
    Tcp(u16),
}

pub enum Sender {
    Tcp(tcp_connections::TcpWriter<Bytes>),
}

pub enum Receiver {
    Tcp(tcp_connections::TcpReader<Bytes>),
}

pub enum Acceptor {
    Tcp(mpsc::Receiver<(TcpStream, SocketAddr)>, TcpListener),
}

pub struct Transport {
    pub receiver:        Receiver,
    pub sender:          Sender,
    pub remote_endpoint: Endpoint,
}

pub fn connect(remote_ep: Endpoint) -> IoResult<Transport> {
    match remote_ep {
        Endpoint::Tcp(ep) => {
            tcp_connections::connect_tcp(ep)
                .map(|(i, o)| Transport{ receiver:        Receiver::Tcp(i),
                                         sender:          Sender::Tcp(o),
                                         remote_endpoint: remote_ep
                                       })
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::NotConnected, e.description())
                })
        }
    }
}

pub fn new_acceptor(port: &Port) -> IoResult<Acceptor> {
    match *port {
        Port::Tcp(ref port) => {
            let (receiver, listener) = try!(tcp_connections::listen(*port));
            Ok(Acceptor::Tcp(receiver, listener))
        }
    }
}

pub fn accept(acceptor: &Acceptor) -> IoResult<Transport> {
    match *acceptor {
        Acceptor::Tcp(ref rx_channel, _) => {
            let (stream, remote_endpoint) = try!(rx_channel.recv()
                .map_err(|e| io::Error::new(io::ErrorKind::NotConnected, e.description())));

            let (i, o) = try!(tcp_connections::upgrade_tcp(stream));

            Ok(Transport{ receiver:        Receiver::Tcp(i),
                          sender:          Sender::Tcp(o),
                          remote_endpoint: Endpoint::Tcp(remote_endpoint)})
        }
    }
}

pub fn receive(receiver: &Receiver) -> IoResult<Bytes> {
    match *receiver {
        Receiver::Tcp(ref r) => r.recv().map_err(|e| {
            io::Error::new(io::ErrorKind::NotConnected, e.description())
        })
    }
}

pub fn send(sender: &mut Sender, bytes: &Bytes) -> IoResult<()> {
    match *sender {
        Sender::Tcp(ref mut s) => s.send(&bytes).map_err(|e| {
            // FIXME: This can be done better.
            io::Error::new(io::ErrorKind::NotConnected, "can't send")
        })
    }
}

pub fn local_endpoint(acceptor: &Acceptor) -> IoResult<Endpoint> {
    match *acceptor {
        Acceptor::Tcp(_, ref listener) => {
            listener.local_addr().map(Endpoint::Tcp)
        }
    }
}

