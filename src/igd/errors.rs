use std::str;
use std::io;
use http_pull_parser::ParserError;
use xml::common::Error as XmlError;

#[derive(Debug)]
pub enum HttpError {
    IoError(io::Error),
    ParsingError(ParserError),
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
pub enum GetExternalIpError {
}

#[derive(Debug)]
pub enum AddAnyPortError {
}
