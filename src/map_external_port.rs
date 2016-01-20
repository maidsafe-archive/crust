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

use config_file_handler::endpoint::{Protocol, Endpoint};
use igd;
use std::io;
use get_if_addrs::get_if_addrs;
use config_file_handler::socket_addr::SocketAddrV4;
use std::net;
use ip::IpAddr;
use std::thread;
use std::time::Duration;

// How long do we wait to receive a response from the IGD?
const IGD_SEARCH_TIMEOUT_SECS: u64 = 1;

pub fn async_map_external_port<Callback>(local_ep: Endpoint, callback: Callback)
    where Callback: FnOnce(io::Result<Vec<(SocketAddrV4, Endpoint)>>) + Send + 'static
{
    let _detach = thread::Builder::new()
                      .name("async_map_external_port".to_owned())
                      .spawn(move || {
                          let res = sync_map_external_port(&local_ep);
                          callback(res);
                      })
                      .unwrap();
}

pub fn sync_map_external_port(local_ep: &Endpoint) -> io::Result<Vec<(SocketAddrV4, Endpoint)>> {
    let is_unspecified = ::util::is_unspecified(&local_ep.ip());

    let local_eps = if !is_unspecified {
        let ip = match local_ep.ip() {
            IpAddr::V4(ip_addr) => ip_addr,
            IpAddr::V6(_) => {
                return Err(io::Error::new(io::ErrorKind::Other,
                                          "Ip v6 not supported by the uPnP library"));
            }
        };
        vec![SocketAddrV4(net::SocketAddrV4::new(ip, local_ep.port()))]
    } else {
        // TODO: Check if we really need to do this, perhaps uPnP can deal
        // with unspecified addresses itself? Also, it doesn't sound right
        // that we want to map one external port to multiple internal
        // endpoints...
        try!(get_if_addrs())
            .into_iter()
            .filter(|iface| !iface.is_loopback())
            .filter_map(|iface| match iface.ip() {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })
            .map(|ip| SocketAddrV4(net::SocketAddrV4::new(ip, local_ep.port())))
            .collect()
    };

    let eps_count = local_eps.len();

    if eps_count == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "No network interface found"));
    }

    let local_port = local_ep.port();
    let mut join_handles = Vec::with_capacity(eps_count);
    for local_ep in local_eps {
        join_handles.push(thread::Builder::new()
                              .name("sync_map_external_port".to_owned())
                              .spawn(move || {
                                  let result = map_external_port(local_ep, local_port);
                                  result.map(|ext_ep| (local_ep, ext_ep))
                              })
                              .unwrap());
    }
    let mut ret = Vec::with_capacity(eps_count);
    for h in join_handles {
        ret.push(try!(h.join().unwrap()));
    }
    Ok(ret)
}

// --- Private helper functions ------------------------------------------------
fn to_io_result<T, E: ::std::fmt::Debug>(error_name: &str, r: Result<T, E>) -> io::Result<T> {
    r.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}: {:?}", error_name, e)))
}

fn map_external_port(local_addr: SocketAddrV4, ext_port: u16) -> io::Result<Endpoint> {
    let gateway = try!(to_io_result("SearchError",
                                    igd::search_gateway_from_timeout(
                                        local_addr.ip().clone(),
                                        Duration::from_secs(IGD_SEARCH_TIMEOUT_SECS))));

    try!(to_io_result("AddPortError",
                      gateway.add_port(igd::PortMappingProtocol::TCP,
                                       ext_port,
                                       (*local_addr).clone(),
                                       0,
                                       "crust")));

    let ext_ip = try!(to_io_result("GetExternalIpError", gateway.get_external_ip()));

    Ok(Endpoint::new(Protocol::Tcp, IpAddr::V4(ext_ip), ext_port))
}

// --- Tests -------------------------------------------------------------------
#[cfg(test)]
mod test {
    use super::*;
    use std::net::Ipv4Addr;
    use ip::IpAddr;
    use std::sync::mpsc;
    use config_file_handler::endpoint::{Protocol, Endpoint};
    use config_file_handler::socket_addr::SocketAddrV4;
    use std::io;
    use util::timed_recv;

    // Ignore because we don't know what (if any) IGD enabled
    // device is on CI machines.
    #[ignore]
    #[test]
    fn upnp() {
        type R = io::Result<Vec<(SocketAddrV4, Endpoint)>>;
        let (sender, receiver) = mpsc::channel::<R>();
        let unspecified_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let local_ep = Endpoint::new(Protocol::Tcp, unspecified_ip, 5484);
        async_map_external_port(local_ep, move |result: R| {
            assert!(sender.send(result).is_ok());
        });

        let igd_result = match timed_recv(&receiver, ::std::time::Duration::from_secs(3)) {
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
