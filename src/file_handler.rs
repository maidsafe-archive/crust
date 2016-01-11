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

use std::path::{Path, PathBuf};
use std::fs;
use std::io;

/// Struct for reading and writing config files.
///
/// # Thread- and Process-Safety
///
/// Since all instances of `FileHandler` initialised with the same value for `name` within a single
/// process will likely refer to the same file on disk, it is not safe to access any such instance
/// concurrently with that same *or any other* such instance (with the exception of the
/// [`path()`](#method.path) function which is the only non-mutating member function).
///
/// For instances initialised with different values for `name`, it is safe to access separate
/// instances concurrently.
///
/// It is possibly unsafe to call [`write_file()`](#method.write_file) concurrently with a different
/// process calling [`read_file()`](#method.read_file) or [`write_file()`](#method.write_file) where
/// both processes have the same name and their instances of `FileHandler` are using the same name,
/// since these may be accessing the same file on disk.  However, it is safe to call
/// [`read_file()`](#method.read_file) concurrently across multiple such processes, since this
/// function doesn't modify the file.
///
/// Perhaps the easiest way to make multi-process access safe is to ensure each process is a single
/// execution of a binary, and that each binary is located in a directory which is
/// mutually-exclusive to all other such binaries, and that each config file to be managed by
/// `FileHandler` is placed in each binary's [`current_bin_dir()`](fn.current_bin_dir.html).  In
/// this way, each process should be the only one accessing that file.
pub struct FileHandler {
    name: ::std::path::PathBuf,
    path: Option<::std::path::PathBuf>,
}

impl FileHandler {
    /// Constructor taking the required file name (not the full path)
    pub fn new(name: ::std::path::PathBuf) -> FileHandler {
        FileHandler {
            name: name,
            path: None,
        }
    }

    /// Reads the file and returns the JSON-decoded contents or an error.
    ///
    /// It tries to read from the following locations in this order (see also [an example config
    /// file flowchart]
    /// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf)):
    ///
    ///   1. The location of the most recent successful read or write attempt
    ///   2. [`current_bin_dir()`](fn.current_bin_dir.html)
    ///   3. [`user_app_dir()`](fn.user_app_dir.html)
    ///   4. [`system_cache_dir()`](fn.system_cache_dir.html)
    ///
    /// See [Thread- and Process-Safety](#thread--and-process-safety) for notes on thread- and
    /// process-safety.
    ///
    /// ## **NOTE**
    ///
    /// If a file (or directory) exists at the expected location when an attempt is made to read it,
    /// and reading or decoding fails, this function **WILL TERMINATE THE APPLICATION.**  This means
    /// that the only cause for an error to be returned from this function is the non-existence of
    /// the file in all attempted locations.
    pub fn read_file<Contents: ::rustc_serialize::Decodable>
        (&mut self)
         -> Result<Contents, ::error::Error> {
        let mut last_error = ::error::Error::NotSet;

        let paths = vec![self.path().clone().ok_or(::error::Error::NotSet),
                         current_bin_dir(),
                         user_app_dir(),
                         system_cache_dir()];

        for path_result in paths {
            match self.set_path(path_result) {
                Ok(mut path) => {
                    path.push(self.name.clone());
                    match Self::read::<Contents>(path.clone()) {
                        Ok(content) => {
                            return Ok(content);
                        }
                        Err(error) => {
                            last_error = error;
                        }
                    }
                }
                Err(error) => {
                    last_error = error;
                }
            }
        }

        self.path = None;
        Err(last_error)
    }

    /// Remove the file from every location where it can be read.
    pub fn cleanup(name: &PathBuf) -> io::Result<()> {
        let i1 = current_bin_dir().into_iter();
        let i2 = user_app_dir().into_iter();
        let i3 = system_cache_dir().into_iter();

        let dirs = i1.chain(i2.chain(i3));

        for mut dir in dirs {
            dir.push(name.clone());
            let path = Path::new(&dir);

            if path.exists() {
                try!(fs::remove_file(path));
            }
        }

        Ok(())
    }

    /// JSON-encodes then writes `contents` to the file.  Creates the file if it doesn't already
    /// exist.
    ///
    /// If `contents` fails to encode or the file cannot be written, an error is returned.  The
    /// process is (see also [an example config file flowchart]
    /// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf)):
    ///
    ///   1. If the file has previously been read (i.e. [`path()`](#method.path) is `Some(...)`), it
    ///      tries to write the contents to this path.  If this fails, it jumps to step 3.
    ///   2. It tries to create and write the file in
    ///      [`system_cache_dir()`](fn.system_cache_dir.html).  It will not try and create this
    ///      directory if it doesn't exist.
    ///   3. It tries to create and write the file in [`user_app_dir()`](fn.user_app_dir.html).  It
    ///      will try to create this directory and any parent components if they don't exist.
    ///
    /// See [Thread- and Process-Safety](#thread--and-process-safety) for notes on thread- and
    /// process-safety.
    pub fn write_file<Contents: ::rustc_serialize::Encodable>(&mut self,
                                                              contents: &Contents)
                                                              -> Result<(), ::error::Error> {
        self.path()
            .clone()
            .ok_or(::error::Error::NotSet)
            .and_then(|mut path| {
                path.push(self.name.clone());
                Self::write(path, contents)
            })
            .or_else(|error| {
                // Only try to create in the sys dir if we've not previously read the file
                match error {
                    ::error::Error::NotSet => {
                        self.set_path(system_cache_dir())
                            .and_then(|mut path| {
                                path.push(self.name.clone());
                                Self::write(path, contents)
                            })
                    }
                    _ => Err(error),
                }
            })
            .or_else(|_| {
                self.set_path(user_app_dir()).and_then(|mut path| {
                    path.push(self.name.clone());
                    Self::write(path, contents)
                })
            })
            .or_else(|_| {
                self.set_path(user_app_dir())
                    .and_then(|path| {
                        try!(::std::fs::create_dir_all(path.clone()));
                        Ok(path)
                    })
                    .and_then(|mut path| {
                        path.push(self.name.clone());
                        Self::write(path, contents)
                    })
            })
            .or_else(|error| {
                self.path = None;
                Err(error)
            })
    }

    /// Get the full path to the file.
    ///
    /// If no calls to [`read_file()`](#method.read_file) or [`write_file()`](#method.write_file)
    /// have been made, or the last such attempt failed, then this will return `None`.
    ///
    /// See [Thread- and Process-Safety](#thread--and-process-safety) for notes on thread- and
    /// process-safety.
    pub fn path(&self) -> &Option<::std::path::PathBuf> {
        &self.path
    }

    fn set_path(&mut self,
                new_path: Result<::std::path::PathBuf, ::error::Error>)
                -> Result<::std::path::PathBuf, ::error::Error> {
        new_path.and_then(|path| {
            // path.push(self.name.clone());
            self.path = Some(path.clone());
            Ok(path)
        })
    }

    fn die(message: String, code: i32) {
        panic!("die with message :{} and exit code {}", message, code);
        // ::std::process::exit(code);
    }

    #[cfg(target_os="windows")]
    fn path_or_file_not_found(error: &::std::io::Error) -> bool {
        let native_error = error.raw_os_error().unwrap_or(0);
        native_error == 2 || native_error == 3
    }

    #[cfg(any(target_os="macos", target_os="ios", target_os="linux"))]
    fn path_or_file_not_found(error: &::std::io::Error) -> bool {
        error.kind() == ::std::io::ErrorKind::NotFound
    }

    fn permission_denied(error: &::std::io::Error) -> bool {
        error.kind() == ::std::io::ErrorKind::PermissionDenied
    }

    #[allow(unsafe_code)]
    fn read<Contents: ::rustc_serialize::Decodable>(path: ::std::path::PathBuf)
                                                    -> Result<Contents, ::error::Error> {
        use rustc_serialize::json::{Json, Decoder};
        use memmap::{Mmap, Protection};
        match ::std::fs::File::open(&path) {
            Ok(file) => {
                let file = match Mmap::open(&file, Protection::Read) {
                    Ok(file) => file,
                    Err(error) => {
                        Self::die(format!("Failed to read {:?}: {}", path, error), 2);
                        unreachable!()
                    }
                };
                let bytes: &[u8] = unsafe { file.as_slice() };
                let mut cursor = io::Cursor::new(bytes);
                match Json::from_reader(&mut cursor)
                          .map_err(|e| format!("{}", e))
                          .and_then(|j| {
                              Contents::decode(&mut Decoder::new(j)).map_err(|e| format!("{}", e))
                          }) {
                    Ok(contents) => Ok(contents),
                    Err(error) => {
                        Self::die(format!("Failed to decode {:?}: {}", path, error), 3);
                        unreachable!();
                    }
                }
            }
            Err(error) => {
                if !Self::path_or_file_not_found(&error) && !Self::permission_denied(&error) {
                    Self::die(format!("Failed to open {:?}: {}", path, error), 1);
                }
                Err(::error::Error::IoError(error))
            }
        }
    }

    #[allow(unsafe_code)]
    fn write<Contents: ::rustc_serialize::Encodable>(path: ::std::path::PathBuf,
                                                     contents: &Contents)
                                                     -> Result<(), ::error::Error> {
        use memmap::{Mmap, Protection};
        use rustc_serialize::json;
        use std::fs::OpenOptions;
        use std::io::Write;
        let contents = format!("{}", json::as_pretty_json(contents)).into_bytes();
        let file = try!(OpenOptions::new().read(true).write(true).create(true).open(path));
        try!(file.set_len(contents.len() as u64));
        let mut mmap = try!(Mmap::open(&file, Protection::ReadWrite));
        try!(unsafe { mmap.as_mut_slice() }.write_all(&contents[..]));
        mmap.flush().map_err(::error::Error::IoError)
    }
}

/// The full path to the directory containing the currently-running binary.  See also [an example
/// config file flowchart]
/// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf).
pub fn current_bin_dir() -> Result<::std::path::PathBuf, ::error::Error> {
    let mut path = try!(::std::env::current_exe());
    let pop_result = path.pop();
    debug_assert!(pop_result);
    Ok(path)
}

/// The full path to an application support directory for the current user.  See also [an example
/// config file flowchart]
/// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf).
#[cfg(target_os="windows")]
pub fn user_app_dir() -> Result<::std::path::PathBuf, ::error::Error> {
    Ok(try!(join_exe_file_stem(::std::path::Path::new(&try!(::std::env::var("APPDATA"))))))
}

/// The full path to an application support directory for the current user.  See also [an example
/// config file flowchart]
/// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf).
#[cfg(any(target_os="macos", target_os="ios", target_os="linux"))]
pub fn user_app_dir() -> Result<::std::path::PathBuf, ::error::Error> {
    Ok(try!(join_exe_file_stem(&try!(::std::env::home_dir().ok_or(not_found_error()))
                                    .join(".config"))))
}

/// The full path to a system cache directory available for all users.  See also [an example config
/// file flowchart]
/// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf).
#[cfg(target_os="windows")]
pub fn system_cache_dir() -> Result<::std::path::PathBuf, ::error::Error> {
    Ok(try!(join_exe_file_stem(::std::path::Path::new(&try!(::std::env::var("ALLUSERSPROFILE"))))))
}

/// The full path to a system cache directory available for all users.  See also [an example config
/// file flowchart]
/// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf).
#[cfg(any(target_os="macos", target_os="ios", target_os="linux"))]
pub fn system_cache_dir() -> Result<::std::path::PathBuf, ::error::Error> {
    join_exe_file_stem(::std::path::Path::new("/var/cache"))
}

/// The file name of the currently-running binary without any suffix or extension.  For example, if
/// the binary is "C:\\Abc.exe" this function will return `Ok("Abc")`.
pub fn exe_file_stem() -> Result<::std::path::PathBuf, ::error::Error> {
    let exe_path = try!(::std::env::current_exe());
    Ok(::std::path::PathBuf::from(try!(exe_path.file_stem().ok_or(not_found_error()))))
}

/// RAII object which removes the [`user_app_dir()`](fn.user_app_dir.html) when an instance is
/// dropped.
///
/// Since the `user_app_dir` is frequently created by tests or examples which use Crust, this is a
/// convenience object which tries to remove the directory when it is destroyed.
///
/// # Examples
///
/// ```
/// {
///     let _cleaner = ::crust::ScopedUserAppDirRemover;
///     let mut file_handler =
///         ::crust::FileHandler::new(::std::path::Path::new("test.json").to_path_buf());
///     // User app dir is possibly created by this call.
///     let _ = file_handler.write_file(&111u64);
/// }
/// // User app dir is now removed since '_cleaner' has gone out of scope.
/// ```
pub struct ScopedUserAppDirRemover;

impl ScopedUserAppDirRemover {
    fn remove_dir(&mut self) {
        let _ = user_app_dir().and_then(|user_app_dir| {
            ::std::fs::remove_dir_all(user_app_dir).map_err(::error::Error::IoError)
        });
    }
}

impl Drop for ScopedUserAppDirRemover {
    fn drop(&mut self) {
        self.remove_dir();
    }
}

fn not_found_error() -> ::std::io::Error {
    ::std::io::Error::new(::std::io::ErrorKind::NotFound, "No file name component")
}

fn join_exe_file_stem(path: &::std::path::Path) -> Result<::std::path::PathBuf, ::error::Error> {
    Ok(path.join(try!(exe_file_stem())))
}

#[cfg(test)]
mod test {
    #[test]
    fn read_write_file_test() {
        let _cleaner = super::ScopedUserAppDirRemover;
        let mut file_handler = super::FileHandler::new(::std::path::Path::new("file_handler_test\
                                                                               .json")
                                                           .to_path_buf());
        let test_value = 123456789u64;

        match file_handler.read_file::<u64>() {
            Ok(result) => {
                assert_eq!(result, test_value);
                assert!(!file_handler.path().is_none());
            }
            Err(_) => assert!(file_handler.path().is_none()),
        }

        match file_handler.write_file(&test_value) {
            Ok(_) => assert!(!file_handler.path().is_none()),
            Err(_) => assert!(file_handler.path().is_none()),
        }

        match file_handler.read_file::<u64>() {
            Ok(result) => {
                assert_eq!(result, test_value);
                assert!(!file_handler.path().is_none());
            }
            Err(_) => assert!(file_handler.path().is_none()),
        }
    }
}
