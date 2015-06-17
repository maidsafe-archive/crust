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

use utp::CloneableSocket as UtpSocket;
use std::net::SocketAddr;
use std::io::Result as IoResult;
use rustc_serialize::{Decodable, Encodable};
use std::sync::mpsc::{Sender, Receiver};

pub type UtpReader<T> = Receiver<T>;
pub type UtpWriter<T> = Sender<T>;

pub type InUtpStream<T> = Receiver<T>;
pub type OutUtpStream<T> = Sender<T>;

/// Connect to a peer and open a send-receive pair.  See `upgrade` for more details.
#[allow(unused)]
pub fn connect_utp<'a, 'b, I, O>(addr: SocketAddr) -> IoResult<(Receiver<I>, Sender<O>)>
        where I: Send + Decodable + 'static, O: Send + Encodable + 'static {
    panic!("UTP support in crust is currently non functional");
}

/// Starts listening for connections on this ip and port.
/// Returns:
/// * A receiver of Utp socket objects.  It is recommended that you `upgrade` these.
#[allow(unused)]
pub fn listen(port: u16) -> IoResult<(Receiver<(UtpSocket, SocketAddr)>, u16)> {
    panic!("UTP support in crust is currently non functional");
}

/// Upgrades a newly connected UtpSocket to a Sender-Receiver pair that you can use to send and
/// receive objects automatically.  If there is an error decoding or encoding
/// values, that respective part is shut down.
#[allow(unused)]
pub fn upgrade_utp<'a, 'b, I, O>(newconnection: UtpSocket) -> IoResult<(Receiver<I>, Sender<O>)>
where I: Send + Decodable + 'static, O: Send + Encodable + 'static {
    panic!("UTP support in crust is currently non functional");
}


