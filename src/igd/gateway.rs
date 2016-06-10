use std::net::{Ipv4Addr, SocketAddrV4};
use std::fmt;
use mio::EventLoop;
use xmltree;
use rand;
use rand::distributions::IndependentSample;
use core::Core;
use igd::soap;
use igd::errors::{AddAnyPortError, RequestError, GetExternalIpError};

#[allow(unused)]
struct Closure<T>(Box<FnMut(T, &mut Core, &mut EventLoop<Core>)>);

impl<T> Closure<T> {
    #[allow(unused)]
    pub fn new<F>(f: F) -> Closure<T>
        where F: FnOnce(T, &mut Core, &mut EventLoop<Core>) + 'static {
        let mut f = Some(f);
        Closure(Box::new(move |res, core, event_loop| {
            if let Some(f) = f.take() {
                f(res, core, event_loop)
            }
        }))
    }

    #[allow(unused)]
    pub fn empty() -> Closure<T> {
        Closure(Box::new(|_, _, _| ()))
    }

    #[allow(unused)]
    pub fn invoke(&mut self, res: T, core: &mut Core,
                  event_loop: &mut EventLoop<Core>) {
        (self.0)(res, core, event_loop)
    }
}

/// Represents the protocols available for port mapping.
#[allow(unused)]
#[derive(Debug,Clone,Copy,PartialEq)]
pub enum PortMappingProtocol {
    /// TCP protocol
    TCP,
    /// UDP protocol
    UDP,
}

impl fmt::Display for PortMappingProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match *self {
            PortMappingProtocol::TCP => "TCP",
            PortMappingProtocol::UDP => "UDP",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[allow(unused)]
/// This structure represents a gateway found by the search functions.
pub struct Gateway {
    /// Socket address of the gateway
    pub addr: SocketAddrV4,
    /// Control url of the device
    pub control_url: String,
}

impl Gateway {
    #[allow(unused)]
    pub fn get_external_ip<F>(&self, core: &mut Core,
                              event_loop: &mut EventLoop<Core>, callback: F)
        where F: FnOnce(Result<Ipv4Addr, GetExternalIpError>, &mut Core,
                        &mut EventLoop<Core>) + 'static {
        // Content of the get external ip SOAPAction request header.
        let header = "\"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"";
        let body = "<?xml version=\"1.0\"?>
        <SOAP-ENV:Envelope SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">
            <SOAP-ENV:Body>
                <m:GetExternalIPAddress xmlns:m=\"urn:schemas-upnp-org:service:WANIPConnection:1\">
                </m:GetExternalIPAddress>
            </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>";

        self.perform_request(header, body, "GetExternalIPAddressResponse".to_string(), core, event_loop, |res, core, event_loop| {
            let res = match res {
                Ok((text, response)) => {
                    match response.get_child("NewExternalIPAddress")
                        .and_then(|e| e.text.as_ref())
                        .and_then(|t| t.parse::<Ipv4Addr>().ok())
                    {
                        Some(ipv4_addr) => Ok(ipv4_addr),
                        None => Err(GetExternalIpError::RequestError(RequestError::InvalidResponse(text))),
                    }
                },
                Err(RequestError::ErrorCode(606, _)) => Err(GetExternalIpError::ActionNotAuthorized),
                Err(e) => Err(GetExternalIpError::RequestError(e)),
            };
            callback(res, core, event_loop);
        });
    }

    #[allow(unused)]
    pub fn add_any_port<F>(&self, core: &mut Core,
                           event_loop: &mut EventLoop<Core>,
                           protocol: PortMappingProtocol,
                           local_addr: SocketAddrV4, lease_duration: u32,
                           description: String, callback: F)
        where F: FnOnce(Result<u16, AddAnyPortError>, &mut Core,
                        &mut EventLoop<Core>) + 'static {
        // This function first attempts to call AddAnyPortMapping on the IGD with a random port
        // number. If that fails due to the method being unknown it attempts to call AddPortMapping
        // instead with a random port number. If that fails due to ConflictInMappingEntry it retrys
        // with another port up to a maximum of 20 times. If it fails due to SamePortValuesRequired
        // it retrys once with the same port values.

        if local_addr.port() == 0 {
            callback(Err(AddAnyPortError::InternalPortZeroInvalid), core,
                     event_loop);
            return;
        }

        let gateway = self.clone();
        let port_range = rand::distributions::Range::new(32768u16, 65535u16);
        let mut rng = rand::thread_rng();
        let external_port = port_range.ind_sample(&mut rng);

        let header = "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddAnyPortMapping\"";
        let body = format!("<?xml version=\"1.0\"?>
        <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
        <s:Body>
            <u:AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">
                <NewProtocol>{}</NewProtocol>
                <NewExternalPort>{}</NewExternalPort>
                <NewInternalClient>{}</NewInternalClient>
                <NewInternalPort>{}</NewInternalPort>
                <NewLeaseDuration>{}</NewLeaseDuration>
                <NewPortMappingDescription>{}</NewPortMappingDescription>
                <NewEnabled>1</NewEnabled>
                <NewRemoteHost></NewRemoteHost>
            </u:AddPortMapping>
        </s:Body>
        </s:Envelope>
        ", protocol, external_port, local_addr.ip(),
                           local_addr.port(), lease_duration, description);

        self.perform_request(header, &*body, "AddAnyPortMappingResponse".to_string(), core, event_loop, move |res, core, event_loop| {
            // First, attempt to call the AddAnyPortMapping method.
            match res {
                Ok((text, response)) => {
                    match response.get_child("NewReservedPort")
                        .and_then(|e| e.text.as_ref())
                        .and_then(|t| t.parse::<u16>().ok())
                    {
                        Some(port) => {
                            callback(Ok(port), core, event_loop);
                            return;
                        }
                        None => {
                            callback(Err(AddAnyPortError::RequestError(RequestError::InvalidResponse(text))),
                                     core, event_loop);
                            return;
                        }
                    }
                }
                // The router doesn't know the AddAnyPortMapping method. Try using AddPortMapping
                // instead.
                Err(RequestError::ErrorCode(401, _)) | Err(RequestError::ErrorCode(500, _)) => {
                    // Try a bunch of random ports.
                    struct Callback<F2: FnOnce(Result<u16, AddAnyPortError>,
                                               &mut Core, &mut EventLoop<Core>)
                                    + 'static> {
                        gateway: Gateway,
                        port_range: rand::distributions::Range<u16>,
                        rng: rand::ThreadRng,
                        external_port: u16,
                        protocol: PortMappingProtocol,
                        local_addr: SocketAddrV4,
                        lease_duration: u32,
                        description: String,
                        callback: Option<F2>,
                        idx: u8,
                    };

                    impl<F2: FnOnce(Result<u16, AddAnyPortError>, &mut Core,
                                    &mut EventLoop<Core>) + 'static>
                        Callback<F2> {
                        fn on_port_mapping(mut self, res: Result<(), RequestError>,
                                           core: &mut Core,
                                           event_loop: &mut EventLoop<Core>) {
                            match res {
                                Ok(_) => {
                                    let res = Ok(self.external_port);
                                    self.notify(res, core, event_loop);
                                    return;
                                }
                                Err(RequestError::ErrorCode(605, _)) => {
                                    let e = AddAnyPortError::DescriptionTooLong;
                                    self.notify(Err(e), core, event_loop);
                                    return;
                                }
                                Err(RequestError::ErrorCode(606, _)) => {
                                    let e = AddAnyPortError::ActionNotAuthorized;
                                    self.notify(Err(e), core, event_loop);
                                    return;
                                }
                                // That port is in use. Try another.
                                Err(RequestError::ErrorCode(718, _)) => {
                                    self.schedule_port_mapping(core,
                                                               event_loop);
                                    return;
                                }
                                // The router requires that internal and
                                // external ports are the same.
                                Err(RequestError::ErrorCode(724, _)) => {
                                    let gateway = self.gateway.clone();
                                    let description = self.description.clone();
                                    gateway.add_port_mapping(core, event_loop, self.protocol, self.local_addr.port(), self.local_addr, self.lease_duration, &description, move |res, core, event_loop| {
                                        match res {
                                            Ok(()) => {
                                                let port = self.local_addr.port();
                                                self.notify(Ok(port), core,
                                                            event_loop);
                                            }
                                            Err(RequestError::ErrorCode(606, _)) => {
                                                let e = AddAnyPortError::ActionNotAuthorized;
                                                self.notify(Err(e), core, event_loop);
                                            }
                                            Err(RequestError::ErrorCode(718, _)) => {
                                                let e = AddAnyPortError::ExternalPortInUse;
                                                self.notify(Err(e), core, event_loop);
                                            }
                                            Err(RequestError::ErrorCode(725, _)) => {
                                                let e = AddAnyPortError::OnlyPermanentLeasesSupported;
                                                self.notify(Err(e), core, event_loop);
                                            }
                                            Err(e) => {
                                                let e = AddAnyPortError::RequestError(e);
                                                self.notify(Err(e), core, event_loop);
                                            }
                                        }
                                    });
                                    return;
                                },
                                Err(RequestError::ErrorCode(725, _)) => {
                                    let e = AddAnyPortError::OnlyPermanentLeasesSupported;
                                    self.notify(Err(e), core, event_loop);
                                    return;
                                }
                                Err(e) => {
                                    let e = AddAnyPortError::RequestError(e);
                                    self.notify(Err(e), core, event_loop);
                                    return;
                                }
                            }
                            // The only way we can get here is if the router kept returning 718 (port in use)
                            // for all the ports we tried.
                            self.notify(Err(AddAnyPortError::NoPortsAvailable),
                                        core, event_loop);
                            return;
                        }

                        fn notify(&mut self, res: Result<u16, AddAnyPortError>,
                                  core: &mut Core,
                                  event_loop: &mut EventLoop<Core>) {
                            if let Some(callback) = self.callback.take() {
                                callback(res, core, event_loop);
                            }
                        }

                        pub fn schedule_port_mapping(mut self, core: &mut Core,
                                                     event_loop: &mut EventLoop<Core>) {
                            if self.idx == 20 {
                                return;
                            }

                            self.external_port = self.port_range.ind_sample(&mut self.rng);
                            self.idx += 1;
                            let gateway = self.gateway.clone();
                            let description = self.description.clone();
                            gateway
                                .add_port_mapping(core, event_loop,
                                                  self.protocol,
                                                  self.external_port,
                                                  self.local_addr,
                                                  self.lease_duration,
                                                  &description,
                                                  move |res, core, event_loop| {
                                                      self.on_port_mapping(res, core,
                                                                           event_loop);
                                                  });
                        }

                        pub fn new(gateway: Gateway,
                                   port_range: rand::distributions::Range<u16>,
                                   mut rng: rand::ThreadRng,
                                   protocol: PortMappingProtocol,
                                   local_addr: SocketAddrV4,
                                   lease_duration: u32, description: String,
                                   callback: F2)
                                   -> Callback<F2> {
                            let external_port = port_range.ind_sample(&mut rng);
                            Callback {
                                gateway: gateway,
                                port_range: port_range,
                                rng: rng,
                                external_port: external_port,
                                protocol: protocol,
                                local_addr: local_addr,
                                lease_duration: lease_duration,
                                description: description,
                                callback: Some(callback),
                                idx: 0,
                            }
                        }
                    }

                    Callback::new(gateway, port_range, rng, protocol,
                                  local_addr, lease_duration, description,
                                  callback)
                        .schedule_port_mapping(core, event_loop);
                    return;
                }
                Err(RequestError::ErrorCode(605, _)) => {
                    callback(Err(AddAnyPortError::DescriptionTooLong), core,
                             event_loop);
                    return;
                }
                Err(RequestError::ErrorCode(606, _)) => {
                    callback(Err(AddAnyPortError::ActionNotAuthorized), core,
                             event_loop);
                }
                Err(RequestError::ErrorCode(728, _)) => {
                    callback(Err(AddAnyPortError::NoPortsAvailable), core,
                             event_loop);
                    return;
                }
                Err(e) => {
                    callback(Err(AddAnyPortError::RequestError(e)), core,
                             event_loop);
                    return;
                }
            }
        });
    }

    #[allow(unused)]
    fn perform_request<F>(&self, header: &str, body: &str, ok: String,
                          core: &mut Core, event_loop: &mut EventLoop<Core>,
                          callback: F)
        where F: FnOnce(Result<(String, xmltree::Element), RequestError>,
                        &mut Core, &mut EventLoop<Core>) + 'static {
        soap::send(&self.addr, &self.control_url, header, body, core, event_loop, move |res, core, event_loop| {
            let text = match res {
                Ok(t) => t,
                Err(e) => {
                    callback(Err(e.into()), core, event_loop);
                    return;
                }
            };
            let mut xml = match xmltree::Element::parse(text.as_bytes()) {
                Ok(xml) => xml,
                Err(..) => {
                    callback(Err(RequestError::InvalidResponse(text)), core,
                             event_loop);
                    return;
                }
            };
            let mut body = match xml.get_mut_child("Body") {
                Some(body) => body,
                None => {
                    callback(Err(RequestError::InvalidResponse(text)), core,
                             event_loop);
                    return;
                }
            };
            if let Some(ok) = body.take_child(ok) {
                callback(Ok((text, ok)), core, event_loop);
                return;
            }
            let upnp_error = match body.get_child("Fault")
                .and_then(|e| e.get_child("detail"))
                .and_then(|e| e.get_child("UPnPError"))
            {
                Some(upnp_error) => upnp_error,
                None => {
                    callback(Err(RequestError::InvalidResponse(text)), core,
                             event_loop);
                    return;
                }
            };
            let res = match (upnp_error.get_child("errorCode"), upnp_error.get_child("errorDescription")) {
                (Some(e), Some(d)) => match (e.text.as_ref(), d.text.as_ref()) {
                    (Some(et), Some(dt)) => {
                        match et.parse::<u16>() {
                            Ok(en)  => Err(RequestError::ErrorCode(en, From::from(&dt[..]))),
                            Err(..) => Err(RequestError::InvalidResponse(text)),
                        }
                    },
                    _ => Err(RequestError::InvalidResponse(text)),
                },
                _ => Err(RequestError::InvalidResponse(text)),
            };
            callback(res, core, event_loop);
        });
    }

    #[allow(unused)]
    fn add_port_mapping<F>(&self, core: &mut Core,
                           event_loop: &mut EventLoop<Core>,
                           protocol: PortMappingProtocol, external_port: u16,
                           local_addr: SocketAddrV4, lease_duration: u32,
                           description: &str, callback: F)
        where F: FnOnce(Result<(), RequestError>, &mut Core,
                        &mut EventLoop<Core>) + 'static {
        let header = "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"";
        let body = format!("<?xml version=\"1.0\"?>
        <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
        <s:Body>
            <u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">
                <NewProtocol>{}</NewProtocol>
                <NewExternalPort>{}</NewExternalPort>
                <NewInternalClient>{}</NewInternalClient>
                <NewInternalPort>{}</NewInternalPort>
                <NewLeaseDuration>{}</NewLeaseDuration>
                <NewPortMappingDescription>{}</NewPortMappingDescription>
                <NewEnabled>1</NewEnabled>
                <NewRemoteHost></NewRemoteHost>
            </u:AddPortMapping>
        </s:Body>
        </s:Envelope>
        ", protocol, external_port, local_addr.ip(),
           local_addr.port(), lease_duration, description);
        self.perform_request(header, &*body,
                             "AddPortMappingResponse".to_string(), core,
                             event_loop, move |res, core, event_loop| {
                                 callback(res.map(|_| ()), core, event_loop);
                             });
    }
}
