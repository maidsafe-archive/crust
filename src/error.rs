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

/// Error types.
#[derive(Debug)]
pub enum Error {
    /// Wrapper for a `::std::env::VarError`
    EnvError(::std::env::VarError),
    /// Wrapper for a `::std::io::Error`
    IoError(::std::io::Error),
    /// Wrapper for a `::rustc_serialize::json::DecoderError`
    JsonDecoderError(::rustc_serialize::json::DecoderError),
    /// Wrapper for a `::rustc_serialize::json::EncoderError`
    JsonEncoderError(::rustc_serialize::json::EncoderError),
    /// Wrapper for a `::cbor::CborError`
    CborError(::cbor::CborError),
    /// Indicates variable has never been set
    NotSet,
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            &Error::EnvError(ref v) => write!(f, "EnvError {}", v),
            &Error::IoError(ref v) => write!(f, "IoError {}", v),
            &Error::JsonDecoderError(ref v) => write!(f, "JsonDecoderError {}", v),
            &Error::JsonEncoderError(ref v) => write!(f, "JsonEncoderError {}", v),
            &Error::CborError(ref v) => write!(f, "CborError {}", v),
            &Error::NotSet => write!(f, "NotSet"),
        }
    }
}

impl From<::std::env::VarError> for Error {
    fn from(error: ::std::env::VarError) -> Self {
        Error::EnvError(error)
    }
}

impl From<::std::io::Error> for Error {
    fn from(error: ::std::io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<::rustc_serialize::json::DecoderError> for Error {
    fn from(error: ::rustc_serialize::json::DecoderError) -> Self {
        Error::JsonDecoderError(error)
    }
}

impl From<::rustc_serialize::json::EncoderError> for Error {
    fn from(error: ::rustc_serialize::json::EncoderError) -> Self {
        Error::JsonEncoderError(error)
    }
}

impl From<::cbor::CborError> for Error {
    fn from(error: ::cbor::CborError) -> Self {
        Error::CborError(error)
    }
}
