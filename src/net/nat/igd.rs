// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use futures::sync::oneshot;
use igd::{self, AddAnyPortError, PortMappingProtocol, SearchError};
use priv_prelude::*;

use std::thread;

#[derive(Debug)]
pub struct SearchGatewayFromTimeout {
    rx: oneshot::Receiver<Result<Gateway, SearchError>>,
}

impl Future for SearchGatewayFromTimeout {
    type Item = Gateway;
    type Error = SearchError;

    fn poll(&mut self) -> Result<Async<Gateway>, SearchError> {
        match unwrap!(self.rx.poll()) {
            Async::Ready(res) => Ok(Async::Ready(res?)),
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}

pub fn search_gateway_from_timeout(ipv4: Ipv4Addr, timeout: Duration) -> SearchGatewayFromTimeout {
    let (tx, rx) = oneshot::channel();
    let _ = thread::spawn(move || {
        let res = igd::search_gateway_from_timeout(ipv4, timeout);
        let res = res.map(|gateway| Gateway { inner: gateway });
        tx.send(res)
    });
    SearchGatewayFromTimeout { rx: rx }
}

#[derive(Debug)]
pub struct Gateway {
    inner: igd::Gateway,
}

#[derive(Debug)]
pub struct GetAnyAddress {
    rx: oneshot::Receiver<Result<SocketAddrV4, AddAnyPortError>>,
}

impl Future for GetAnyAddress {
    type Item = SocketAddrV4;
    type Error = AddAnyPortError;

    fn poll(&mut self) -> Result<Async<SocketAddrV4>, AddAnyPortError> {
        match unwrap!(self.rx.poll()) {
            Async::Ready(res) => Ok(Async::Ready(res?)),
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}

impl Gateway {
    pub fn get_any_address(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> GetAnyAddress {
        let gateway = self.inner.clone();
        let description = String::from(description);
        let (tx, rx) = oneshot::channel();
        let _ = thread::spawn(move || {
            let res = gateway.get_any_address(protocol, local_addr, lease_duration, &description);
            tx.send(res)
        });
        GetAnyAddress { rx: rx }
    }
}
