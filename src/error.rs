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
use config_file_handler;
use maidsafe_utilities::serialisation;

/// Error types.
#[derive(Debug)]
pub enum Error {
    /// Failed sending over a channel
    ChannelSendError(String),
    /// File handling errors
    FileHandler(config_file_handler::Error),
    /// Wrapper for a `::std::env::VarError`
    EnvError(::std::env::VarError),
    /// Wrapper for a `::std::io::Error`
    IoError(::std::io::Error),
    /// Wrapper for a `::rustc_serialize::json::DecoderError`
    JsonDecoderError(::rustc_serialize::json::DecoderError),
    /// Wrapper for a `::rustc_serialize::json::EncoderError`
    JsonEncoderError(::rustc_serialize::json::EncoderError),
    /// Wrapper for a `rustc_serialize::json::ParserError`
    JsonParserError(::rustc_serialize::json::ParserError),
    /// Wrapper for a `maidsafe_utilities::serialisation::SerialisationError`
    SerialisationError(serialisation::SerialisationError),
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

impl From<::rustc_serialize::json::ParserError> for Error {
    fn from(error: ::rustc_serialize::json::ParserError) -> Self {
        Error::JsonParserError(error)
    }
}
impl From<config_file_handler::Error> for Error {
    fn from(error: config_file_handler::Error) -> Self {
        Error::FileHandler(error)
    }
}

impl From<serialisation::SerialisationError> for Error {
    fn from(error: serialisation::SerialisationError) -> Self {
        Error::SerialisationError(error)
    }
}
