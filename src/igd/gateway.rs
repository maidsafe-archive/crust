use std::net::{Ipv4Addr, SocketAddrV4};
use mio::EventLoop;
use xmltree;
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
                           event_loop: &mut EventLoop<Core>, callback: F)
        where F: FnOnce(Result<u16, AddAnyPortError>) + 'static {
        unimplemented!();
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
}
