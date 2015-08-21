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

#[derive(Debug)]
pub enum Error {
    EnvError(::std::env::VarError),
    IoError(::std::io::Error),
}

impl From<::std::env::VarError> for Error {
    fn from(e: ::std::env::VarError) -> Self {
        Error::EnvError(e)
    }
}

impl From<::std::io::Error> for Error {
    fn from(e: ::std::io::Error) -> Self {
        Error::IoError(e)
    }
}



#[derive(PartialEq, Eq, Hash, Debug, Clone, RustcDecodable, RustcEncodable)]
pub struct Contact {
    pub endpoint: ::transport::Endpoint
}

pub type Contacts = Vec<Contact>;



pub fn current_bin_dir() -> Result<::std::path::PathBuf, Error> {
    let mut path = try!(::std::env::current_exe());
    let pop_result = path.pop();
    debug_assert!(pop_result);
    Ok(path)
}

#[cfg(target_os="windows")]
pub fn user_app_dir() -> Result<::std::path::PathBuf, Error> {
    Ok(try!(join_exe_name(::std::path::Path::new(&try!(::std::env::var("APPDATA"))))))
}

#[cfg(any(target_os="macos", target_os="ios", target_os="linux"))]
pub fn user_app_dir() -> Result<::std::path::PathBuf, Error> {
    Ok(try!(join_exe_name(&try!(::std::env::home_dir().ok_or(not_found_error())).join(".config"))))
}

#[cfg(target_os="windows")]
pub fn system_cache_dir() -> Result<::std::path::PathBuf, Error> {
    Ok(try!(join_exe_name(::std::path::Path::new(&try!(::std::env::var("ALLUSERSPROFILE"))))))
}

#[cfg(any(target_os="macos", target_os="ios", target_os="linux"))]
pub fn system_cache_dir() -> Result<::std::path::PathBuf, Error> {
    join_exe_name(::std::path::Path::new("/var/cache"))
}

#[cfg(any(target_os="windows", target_os="macos", target_os="ios", target_os="linux"))]
fn not_found_error() -> ::std::io::Error {
    ::std::io::Error::new(::std::io::ErrorKind::NotFound, "No file name component")
}

#[cfg(any(target_os="windows", target_os="macos", target_os="ios", target_os="linux"))]
fn join_exe_name(path: &::std::path::Path) -> Result<::std::path::PathBuf, Error> {
    let exe_path = try!(::std::env::current_exe());
    let exe_name = try!(exe_path.file_stem().ok_or(not_found_error()));
    Ok(path.join(exe_name))
}
