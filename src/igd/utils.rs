use std::net::{Ipv4Addr, SocketAddrV4};
use std::io;
use xml::EventReader;
use xml::reader::events::XmlEvent;
#[allow(unused)]
use xmltree;
use regex::Regex;
use core::Core;
use mio::EventLoop;
use http_pull_parser::HttpToken;
use igd::errors::{HttpError, SearchError};
use igd::http_request;

pub fn get_control_url<F>(location: &(SocketAddrV4, String), core: &mut Core,
                          event_loop: &mut EventLoop<Core>, f: F)
    where F: FnOnce(Result<String, SearchError>, &mut Core,
                    &mut EventLoop<Core>) + 'static {
    http_request::get(&location.0, &location.1, core, event_loop, move |res, core, event_loop| -> () {
        let resp = match res {
            Ok(tokens) => {
                match tokens.first() {
                    Some(&HttpToken::Status(200, _)) => (),
                    _ => {
                        f(Err(SearchError::HttpError(HttpError::Unsupported)),
                          core, event_loop);
                        return;
                    }
                }
                let mut body = Vec::new();
                for t in tokens.into_iter().skip(1) {
                    if let HttpToken::Body(mut chunk) = t {
                        body.append(&mut chunk);
                    }
                }
                io::Cursor::new(body)
            }
            Err(e) => {
                f(Err(SearchError::HttpError(e)), core, event_loop);
                return;
            }
        };

        let mut parser = EventReader::new(resp);
        let mut chain = Vec::<String>::with_capacity(4);

        struct Service {
            service_type: String,
            control_url: String,
        }

        let mut service = Service{
            service_type: "".to_string(),
            control_url: "".to_string(),
        };

        for e in parser.events() {
            match e {
                XmlEvent::StartElement { name, .. } => {
                    chain.push(name.to_repr());
                    let tail = if chain.len() >= 3 {
                        chain.iter().skip(chain.len() - 3)
                    } else {
                        continue
                    };

                    if vec!["device", "serviceList", "service"]
                        .iter()
                        .zip(tail)
                        .all(|(l, r)| l == r) {
                            service.service_type.clear();
                            service.control_url.clear();
                        }
                },
                XmlEvent::EndElement { .. } => {
                    let top = chain.pop();
                    let tail = if top == Some("service".to_string())
                        && chain.len() >= 2 {
                            chain.iter().skip(chain.len() - 2)
                        } else {
                            continue
                        };

                    if vec!["device", "serviceList"]
                        .iter()
                        .zip(tail)
                        .all(|(l, r)| l == r) {
                            if "urn:schemas-upnp-org:service:WANIPConnection:1"
                                == service.service_type
                                && service.control_url.len() != 0 {
                                    f(Ok(service.control_url), core, event_loop);
                                    return;
                                }
                        }
                },
                XmlEvent::Characters(text) => {
                    let tail = if chain.len() >= 4 {
                        chain.iter().skip(chain.len() - 4)
                    } else {
                        continue
                    };

                    if vec!["device", "serviceList", "service", "serviceType"]
                        .iter().zip(tail.clone()).all(|(l, r)| l == r) {
                            service.service_type.push_str(&text);
                        }
                    if vec!["device", "serviceList", "service", "controlURL"]
                        .iter().zip(tail).all(|(l, r)| l == r) {
                            service.control_url.push_str(&text);
                        }
                },
                XmlEvent::Error(e) =>  {
                    f(Err(SearchError::XmlError(e)), core, event_loop);
                    return;
                }
                _ => (),
            }
        }
        f(Err(SearchError::InvalidResponse), core, event_loop);
        return;
    });
}

// Parse the result.
pub fn parse_result(text: &str) -> Option<(SocketAddrV4, String)> {
    let re = Regex::new(r"(?i:Location):\s*http://(\d+\.\d+\.\d+\.\d+):(\d+)(/[^\r]*)").unwrap();
    for line in text.lines() {
        match re.captures(line) {
            None => continue,
            Some(cap) => {
                // these shouldn't fail if the regex matched.
                let addr = cap.at(1).unwrap();
                let port = cap.at(2).unwrap();
                return Some(
                    (SocketAddrV4::new(
                        addr.parse::<Ipv4Addr>().unwrap(),
                        port.parse::<u16>().unwrap()),
                     cap.at(3).unwrap().to_string()));
            },
        }
    }
    None
}
