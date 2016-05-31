use std::str;
use std::io;
use std::fmt;
use std;
use http_pull_parser::ParserError;
use xml::common::Error as XmlError;
use igd::soap;

#[derive(Debug)]
pub enum HttpError {
    IoError(io::Error),
    ParsingError(ParserError),
    /// The network uses HTTP features that we don't support (yet!)
    Unsupported,
}

impl std::error::Error for HttpError {
    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            HttpError::IoError(ref e)   => Some(e),
            HttpError::ParsingError(..) => None,
            HttpError::Unsupported      => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            HttpError::IoError(ref e)   => "IO error",
            HttpError::ParsingError(..) => "parsing error",
            HttpError::Unsupported      => "unsupported http feature",
        }
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HttpError::IoError(ref e) => write!(f, "IO error. {}", e),
            HttpError::ParsingError(ref e) => write!(f, "Parsing error: {}", e),
            HttpError::Unsupported => write!(f, "Unsupported HTTP feature. "),
        }
    }
}

#[derive(Debug)]
/// Errors than can occur while trying to find the gateway.
pub enum SearchError {
    /// Http error
    HttpError(HttpError),
    /// Unable to process the response
    InvalidResponse,
    /// IO Error
    IoError(io::Error),
    /// UTF-8 decoding error
    Utf8Error(str::Utf8Error),
    /// XML processing error
    XmlError(XmlError),
}

#[derive(Debug)]
/// Errors that can occur when sending the request to the gateway.
pub enum RequestError {
    /// Http/Hyper error
    HttpError(HttpError),
    /// IO Error
    IoError(io::Error),
    /// The response from the gateway could not be parsed.
    InvalidResponse(String),
    /// The gateway returned an unhandled error code and description.
    ErrorCode(u16, String),
}

impl From<io::Error> for RequestError {
    fn from(err: io::Error) -> RequestError {
        RequestError::IoError(err)
    }
}

impl From<soap::Error> for RequestError {
    fn from(err: soap::Error) -> RequestError {
        match err {
            soap::Error::HttpError(e) => RequestError::HttpError(e),
            soap::Error::IoError(e) => RequestError::IoError(e),
            soap::Error::InvalidResponse => {
                RequestError::InvalidResponse("invalid response".to_string())
            }
        }
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RequestError::HttpError(ref e) => write!(f, "HTTP error. {}", e),
            RequestError::InvalidResponse(ref e) => write!(f, "Invalid response from gateway: {}", e),
            RequestError::IoError(ref e) => write!(f, "IO error. {}", e),
            RequestError::ErrorCode(n, ref e) => write!(f, "Gateway response error {}: {}", n, e),
        }
    }
}

impl std::error::Error for RequestError {
    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            RequestError::HttpError(ref e)     => Some(e),
            RequestError::InvalidResponse(..)  => None,
            RequestError::IoError(ref e)       => Some(e),
            RequestError::ErrorCode(..)        => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            RequestError::HttpError(..)       => "Http error",
            RequestError::InvalidResponse(..) => "Invalid response",
            RequestError::IoError(..)         => "IO error",
            RequestError::ErrorCode(_, ref e) => &e[..],
        }
    }
}

#[derive(Debug)]
/// Errors returned by `Gateway::get_external_ip`
pub enum GetExternalIpError {
    /// The client is not authorized to perform the operation.
    ActionNotAuthorized,
    /// Some other error occured performing the request.
    RequestError(RequestError),
}

#[derive(Debug)]
pub enum AddAnyPortError {
}
