use priv_prelude::*;

use std::net::{SocketAddrV4, Ipv4Addr};
use std::time::Duration;
use std::thread;
use igd::{self, PortMappingProtocol, SearchError, AddAnyPortError};
use futures::{Async, Future};
use futures::sync::oneshot;

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

pub fn search_gateway_from_timeout(
    ipv4: Ipv4Addr,
    timeout: Duration,
) -> SearchGatewayFromTimeout {
    let (tx, rx) = oneshot::channel();
    let _ = thread::spawn(move || {
        let res = igd::search_gateway_from_timeout(ipv4, timeout);
        let res = res.map(|gateway| Gateway { inner: gateway });
        tx.send(res)
    });
    SearchGatewayFromTimeout {
        rx: rx,
    }
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
            let res = gateway.get_any_address(
                protocol,
                local_addr,
                lease_duration,
                &description,
            );
            tx.send(res)
        });
        GetAnyAddress {
            rx: rx,
        }
    }
}

