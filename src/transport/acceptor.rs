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

use std::io;
use utp::UtpListener;
use std::net::TcpListener;
use endpoint::{Endpoint, Port};

pub enum Acceptor {
    // TCP listener
    Tcp(TcpListener),
    // UTP listener
    Utp(UtpListener),
}

impl Acceptor {
    pub fn new(port: Port) -> io::Result<Acceptor> {
        match port {
            Port::Tcp(port) => {
                let listener = {
                    if let Ok(listener) = TcpListener::bind(("0.0.0.0", port)) {
                        listener
                    } else {
                        try!(TcpListener::bind(("0.0.0.0", 0)))
                    }
                };

                Ok(Acceptor::Tcp(listener))
            }
            Port::Utp(port) => {
                let listener = try!(UtpListener::bind(("0.0.0.0", port)));
                Ok(Acceptor::Utp(listener))
            }
        }
    }

    pub fn local_port(&self) -> Port {
        self.local_addr().get_port()
    }

    pub fn local_addr(&self) -> Endpoint {
        match *self {
            Acceptor::Tcp(ref listener) => Endpoint::Tcp(listener.local_addr().unwrap()),
            Acceptor::Utp(ref listener) => Endpoint::Utp(listener.local_addr().unwrap()),
        }
    }
}
