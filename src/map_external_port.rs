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

use ip;
use igd;
use std::io;
use getifaddrs::{getifaddrs, filter_loopback};
use std::net::{IpAddr, SocketAddrV4};
use std::thread;
use std::boxed::FnBox;
use std::time::Duration;

// How long do we wait to receive a response from the IGD?
const IGD_SEARCH_TIMEOUT_SECS: u64 = 1;

pub fn async_map_external_port<Callback>(local_ep: ip::Endpoint, callback: Box<Callback>)
    where Callback: FnBox(io::Result<Vec<(SocketAddrV4, ip::Endpoint)>>) +
          Send + 'static
{
    let _detach = thread::spawn(move || {
        let res = sync_map_external_port(&local_ep);
        callback.call_box((res,));
    });
}

pub fn sync_map_external_port(local_ep: &ip::Endpoint) -> io::Result<Vec<(SocketAddrV4, ip::Endpoint)>>
{
    let is_unspecified = match local_ep.ip() {
        IpAddr::V4(addr) => addr.is_unspecified(),
        IpAddr::V6(addr) => addr.is_unspecified(),
    };

    let local_eps = if !is_unspecified {
        let ip = match local_ep.ip() {
            IpAddr::V4(ip_addr) => ip_addr,
            IpAddr::V6(_) => {
                return Err(io::Error::new(io::ErrorKind::Other,
                                           "Ip v6 not supported by the uPnP library"));
            }
        };
        vec![SocketAddrV4::new(ip, local_ep.port().number())]
    }
    else {
        // TODO: Check if we really need to do this, perhaps uPnP can deal
        // with unspecified addresses itself? Also, it doesn't sound right
        // that we want to map one external port to multiple internal
        // endpoints...
        filter_loopback(getifaddrs())
            .into_iter()
            .filter_map(|e| match e.addr {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })
            .map(|ip| SocketAddrV4::new(ip, local_ep.port().number()))
            .collect::<Vec<_>>()
    };

    let eps_count = local_eps.len();

    if eps_count == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "No network interface found"));
    }

    let local_port = local_ep.port();
    let mut join_handles = Vec::with_capacity(eps_count);
    for local_ep in local_eps {
        join_handles.push(thread::spawn(move || {
            let result = map_external_port(local_ep, local_port);
            result.map(|ext_ep| (local_ep, ext_ep))
        }));
    };
    let mut ret = Vec::with_capacity(eps_count);
    for h in join_handles {
        ret.push(try!(h.join().unwrap()));
    }
    Ok(ret)
}

// --- Private helper functions ------------------------------------------------
fn from_search_result<T>(r: Result<T, igd::SearchError>) -> io::Result<T> {
    r.map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("SearchError: {:?}", e))
    })
}

fn from_request_result<T>(r: Result<T, igd::RequestError>) -> io::Result<T> {
    r.map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("RequestError: {:?}", e))
    })
}

fn map_external_port(local_ep: SocketAddrV4, ext_port: ip::Port)
    -> io::Result<ip::Endpoint>
{
    let gateway = try!(from_search_result(igd::search_gateway_from_timeout(
                            local_ep.ip().clone(), 
                            Duration::from_secs(IGD_SEARCH_TIMEOUT_SECS))));

    let igd_protocol = match &ext_port {
        &ip::Port::Tcp(_) => igd::PortMappingProtocol::TCP,
        &ip::Port::Udp(_) => igd::PortMappingProtocol::UDP,
    };

    try!(from_request_result(gateway.add_port(igd_protocol,
                                              ext_port.number(),
                                              local_ep,
                                              0,
                                              "crust")));

    let ext_ip = try!(from_request_result(gateway.get_external_ip()));

    Ok(ip::Endpoint::new(IpAddr::V4(ext_ip), ext_port))
}

// --- Tests -------------------------------------------------------------------
#[cfg(test)]
mod test {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
    use std::sync::mpsc;
    use ip;
    use std::io;
    use util::timed_recv;

    // Ignore because we don't know what (if any) IGD enabled
    // device is on CI machines.
    #[ignore]
    #[test]
    fn upnp() {
        type R = io::Result<Vec<(SocketAddrV4, ip::Endpoint)>>;
        let (sender, receiver) = mpsc::channel::<R>();
        let unspecified_ip = IpAddr::V4(Ipv4Addr::new(0,0,0,0));
        let local_ep = ip::Endpoint::new(unspecified_ip, ip::Port::Udp(5484));
        async_map_external_port(local_ep, Box::new(move |result: R| {
            assert!(sender.send(result).is_ok());
        }));

        let igd_result = match timed_recv(&receiver, 3000) {
            Ok(igd_result) => igd_result,
            Err(what) => panic!(what),
        };

        let endpoints = match igd_result {
            Ok(endpoints) => endpoints,
            Err(what) => panic!(what),
        };

        assert!(endpoints.len() >= 1);
    }
}

