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

use transport::{Endpoint, Port};
use std::sync::{Arc, Mutex};
use igd;
use getifaddrs::{getifaddrs, filter_loopback};
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::thread;

pub fn map_external_port(port: &Port)
                     -> Vec<(Endpoint, Arc<Mutex<Option<Endpoint>>>)> {
    let (protocol, port_number) = match *port {
        Port::Tcp(port) => (igd::PortMappingProtocol::TCP, port),
        Port::Utp(port) => (igd::PortMappingProtocol::UDP, port),
    };
    // Removing loopback address
    filter_loopback(getifaddrs()).into_iter().filter_map(|e| match e.addr {
        IpAddr::V4(a) => {
            let addr = SocketAddrV4::new(a, port_number);
            let ext = Arc::new(Mutex::new(None));
            let ext2 = ext.clone();
            let port2 = port.clone();

            let _ = thread::spawn(move || {
                match igd::search_gateway_from(addr.ip().clone()) {
                    Ok(gateway) => {
                        let _ = gateway.add_port(protocol, port_number,
                                                 addr.clone(), 0, "crust");

                        match gateway.get_external_ip() {
                            Ok(ip) => {
                                let endpoint = SocketAddr
                                    ::V4(SocketAddrV4::new(ip, port_number));
                                let mut data = ext2.lock().unwrap();
                                *data = Some(match port2 {
                                    Port::Tcp(_) => Endpoint::Tcp(endpoint),
                                    Port::Utp(_) => Endpoint::Utp(endpoint),
                                })
                            },
                            Err(_) => (),
                        }
                    },
                    Err(_) => (),
                }
            });

            let addr = SocketAddr::V4(addr);
            Some((match *port {
                Port::Tcp(_) => Endpoint::Tcp(addr),
                Port::Utp(_) => Endpoint::Utp(addr),
            }, ext))
        },
        _ => None,
    }).collect::<Vec<_>>()
}

