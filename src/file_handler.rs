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

/// Struct for reading and writing to config files
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
    /// It tries to read from the following locations in this order:
    ///
    ///   1. The location of the most recent successful read or write attempt
    ///   2. [`current_bin_dir()`](fn.current_bin_dir.html)
    ///   3. [`user_app_dir()`](fn.user_app_dir.html)
    ///   4. [`system_cache_dir()`](fn.system_cache_dir.html)
    pub fn read_file<Contents: ::rustc_serialize::Decodable>(&mut self) ->
            Result<Contents, ::error::Error> {
        self.path().clone().ok_or(::error::Error::NotSet).and_then(Self::read)
            .or_else(|_| self.set_path(current_bin_dir()).and_then(Self::read))
            .or_else(|_| self.set_path(user_app_dir()).and_then(Self::read))
            .or_else(|_| self.set_path(system_cache_dir()).and_then(Self::read))
            .or_else(|error| {
                self.path = None;
                Err(error)
            })
    }

    /// JSON-encodes then writes `contents` to the file.  Creates the file if it doesn't already
    /// exist.
    ///
    /// If `contents` fails to encode or the file cannot be written, an error is returned.  The
    /// process is:
    ///
    ///   1. If the file has previously been read (i.e. [`path()`](#method.path) is `Some(...)`), it
    ///      tries to write the contents to this path.  If this fails, it jumps to step 3.
    ///   2. It tries to create and write the file in
    ///      [`system_cache_dir()`](fn.system_cache_dir.html).  It will not try and create this
    ///      directory if it doesn't exist.
    ///   3. It tries to create and write the file in [`user_app_dir()`](fn.user_app_dir.html).  It
    ///      will try to create this directory and any parent components if they don't exist.
    pub fn write_file<Contents: ::rustc_serialize::Encodable>(&mut self, contents: &Contents) ->
            Result<(), ::error::Error> {
        self.path().clone().ok_or(::error::Error::NotSet)
            .and_then(|path| Self::write(path, contents))
            .or_else(|error| {
                // Only try to create in the sys dir if we've not previously read the file
                match error {
                    ::error::Error::NotSet =>
                        self.set_path(system_cache_dir())
                            .and_then(|path| Self::write(path, contents)),
                    _ => Err(error),
                }
            })
            .or_else(|_| self.set_path(user_app_dir()).and_then(|path| Self::write(path, contents)))
            .or_else(|_| self.set_path(user_app_dir())
                             .and_then(|path| {
                                 let mut parent = path.clone();
                                 let _ = parent.pop();
                                 try!(::std::fs::create_dir_all(parent));
                                 Ok(path)
                             })
                             .and_then(|path| Self::write(path, contents)))
            .or_else(|error| {
                self.path = None;
                Err(error)
            })
    }

    /// Get the full path to the file.
    ///
    /// If no calls to [`read_file()`](#method.read_file) or [`write_file()`](#method.write_file)
    /// have been made, or the last such attempt failed, then this will return `None`.
    pub fn path(&self) -> &Option<::std::path::PathBuf> {
        &self.path
    }

    fn set_path(&mut self, new_path: Result<::std::path::PathBuf, ::error::Error>) ->
            Result<::std::path::PathBuf, ::error::Error> {
        new_path.and_then(|mut path| {
            path.push(self.name.clone());
            self.path = Some(path.clone());
            Ok(path)
        })
    }

    fn read<Contents: ::rustc_serialize::Decodable>(path: ::std::path::PathBuf) ->
            Result<Contents, ::error::Error> {
        use std::io::Read;
        let mut file = try!(::std::fs::File::open(path));
        let mut encoded_contents = String::new();
        let _ = try!(file.read_to_string(&mut encoded_contents));
        Ok(try!(::rustc_serialize::json::decode(&encoded_contents)))
    }

    fn write<Contents: ::rustc_serialize::Encodable>(path: ::std::path::PathBuf,
                                                     contents: &Contents) ->
            Result<(), ::error::Error> {
        use std::io::Write;
        let mut file = try!(::std::fs::File::create(path));
        let _ = try!(write!(&mut file, "{}", ::rustc_serialize::json::as_pretty_json(contents)));
        file.sync_all().map_err(|error| ::error::Error::IoError(error))
    }
}

/// The full path to the directory containing currently-running binary.
pub fn current_bin_dir() -> Result<::std::path::PathBuf, ::error::Error> {
    let mut path = try!(::std::env::current_exe());
    let pop_result = path.pop();
    debug_assert!(pop_result);
    Ok(path)
}

/// The full path to an application support directory for the current user.
#[cfg(target_os="windows")]
pub fn user_app_dir() -> Result<::std::path::PathBuf, ::error::Error> {
    Ok(try!(join_exe_file_stem(::std::path::Path::new(&try!(::std::env::var("APPDATA"))))))
}

/// The full path to an application support directory for the current user.
#[cfg(any(target_os="macos", target_os="ios", target_os="linux"))]
pub fn user_app_dir() -> Result<::std::path::PathBuf, ::error::Error> {
    Ok(try!(join_exe_file_stem(&try!(::std::env::home_dir().ok_or(not_found_error()))
                              .join(".config"))))
}

/// The full path to a system cache directory available for all users.
#[cfg(target_os="windows")]
pub fn system_cache_dir() -> Result<::std::path::PathBuf, ::error::Error> {
    Ok(try!(join_exe_file_stem(::std::path::Path::new(&try!(::std::env::var("ALLUSERSPROFILE"))))))
}

/// The full path to a system cache directory available for all users.
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
///     // User app dir is now removed since '_cleaner' goes out of scope.
/// }
/// ```
pub struct ScopedUserAppDirRemover;

impl ScopedUserAppDirRemover {
    fn remove_dir(&mut self) {
        let _ = user_app_dir().and_then(|user_app_dir|
                                            ::std::fs::remove_dir_all(user_app_dir)
                                                .map_err(|error| ::error::Error::IoError(error)));
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
        let mut file_handler =
            super::FileHandler::new(::std::path::Path::new("file_handler_test.json").to_path_buf());
        let test_value = 123456789u64;

        match file_handler.read_file::<u64>() {
            Ok(result) => {
                assert_eq!(result, test_value);
                assert!(!file_handler.path().is_none());
            },
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
            },
            Err(_) => assert!(file_handler.path().is_none()),
        }
    }
}
