use std::io::{self, Read};
use std::net::SocketAddrV4;
use mio::EventLoop;
use core::Core;
use http_pull_parser::HttpToken;
use url::{Position, Url};
use igd::http_request;
use igd::errors::HttpError;

#[allow(unused)]
pub enum Error {
    HttpError(HttpError),
    IoError(io::Error),
    InvalidInput,
    ErrorCode(u16, String),
}

impl From<HttpError> for Error {
    fn from(err: HttpError) -> Error {
        Error::HttpError(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

#[allow(unused)]
pub fn send<F>(addr: &SocketAddrV4, control_url: &str, action: &str,
               body: &str, core: &mut Core, event_loop: &mut EventLoop<Core>,
               callback: F)
    where F: FnOnce(Result<String, Error>, &mut Core,
                    &mut EventLoop<Core>) + 'static {
    let (path, domain) = match Url::parse(control_url) {
        Ok(u) => {
            (u[Position::BeforePath..].to_string(),
             u.domain().map(|d| d.to_string())
             .unwrap_or(format!("{}", addr)))
        }
        Err(_) => {
            callback(Err(Error::InvalidInput), core, event_loop);
            return;
        }
    };
    let domain = format!("Host: {}", domain);
    let header = format!("SOAPAction: {}", action);
    let mut req = format!("POST {} HTTP/1.1\r\n{}\r\nContent-Length: {}\r\n{}\r\n\r\n",
                          path, domain, body.len(), header).into_bytes();
    req.extend(body.as_bytes());
    http_request::raw(addr, req, core, event_loop, move |res, core, event_loop| {
        let mut resp = match res {
            Ok(tokens) => {
                match tokens.first() {
                    Some(&HttpToken::Status(200, _)) => (),
                    Some(&HttpToken::Status(code, ref reason)) => {
                        callback(Err(Error::ErrorCode(code, reason.clone())),
                                 core, event_loop);
                        return;
                    }
                    _ => {
                        callback(Err(Error::HttpError(HttpError::Unsupported)),
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
                callback(Err(Error::HttpError(e)), core, event_loop);
                return;
            }
        };

        let mut text = String::new();
        let _ = match resp.read_to_string(&mut text) {
            Ok(_) => callback(Ok(text), core, event_loop),
            Err(e) => {
                let e = Error::IoError(io::Error::new(io::ErrorKind::InvalidData,
                                                      e));
                callback(Err(e), core, event_loop);
            }
        };
    });
}
