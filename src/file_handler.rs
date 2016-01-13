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

use std::path::Path;
use std::ffi::{OsStr, OsString};
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
    path: ::std::path::PathBuf,
}

impl FileHandler {
    /// Constructor taking the required file name (not the full path)
    ///
    /// This function tests whether it has write access to the file in the following locations in
    /// this order (see also [an example config file flowchart]
    /// (https://github.com/maidsafe/crust/blob/master/docs/vault_config_file_flowchart.pdf)):
    ///
    ///   1. [`current_bin_dir()`](fn.current_bin_dir.html)
    ///   2. [`user_app_dir()`](fn.user_app_dir.html)
    ///   3. [`system_cache_dir()`](fn.system_cache_dir.html)
    ///
    /// See [Thread- and Process-Safety](#thread--and-process-safety) for notes on thread- and
    /// process-safety.
    pub fn new<S: AsRef<OsStr> + ?Sized>(name: &S) -> Result<FileHandler, ::error::Error> {
        let name = name.as_ref();
        let mut path = try!(current_bin_dir());
        path.push(name);
        match fs::OpenOptions::new().write(true).create(true).open(&path) {
            Ok(_) => return Ok(FileHandler { path: path }),
            Err(_) => (),
        };

        let mut path = try!(user_app_dir());
        path.push(name);
        match fs::OpenOptions::new().write(true).create(true).open(&path) {
            Ok(_) => return Ok(FileHandler { path: path }),
            Err(_) => (),
        };

        let mut path = try!(system_cache_dir());
        path.push(name);
        match fs::OpenOptions::new().write(true).create(true).open(&path) {
            Ok(_) => Ok(FileHandler { path: path }),
            Err(e) => Err(From::from(e)),
        }
    }

    /// Remove the file from every location where it can be read.
    pub fn cleanup<S: AsRef<OsStr>>(name: &S) -> io::Result<()> {
        let name = name.as_ref();
        let i1 = current_bin_dir().into_iter();
        let i2 = user_app_dir().into_iter();
        let i3 = system_cache_dir().into_iter();

        let dirs = i1.chain(i2.chain(i3));

        for mut path in dirs {
            path.push(name);
            if path.exists() {
                try!(fs::remove_file(path));
            }
        }

        Ok(())
    }

    /// Get the full path to the file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the contents of the file and decode it as JSON.
    #[allow(unsafe_code)]
    pub fn read_file<Contents: ::rustc_serialize::Decodable>
        (&self)
         -> Result<Contents, ::error::Error> {
        use rustc_serialize::json::{Json, Decoder};
        use memmap::{Mmap, Protection};
        let file = try!(::std::fs::File::open(&self.path));
        // TODO Replace with facilitites from fs2
        let file = try!(Mmap::open(&file, Protection::Read));
        let bytes: &[u8] = unsafe { file.as_slice() };
        let mut cursor = io::Cursor::new(bytes);
        let json = try!(Json::from_reader(&mut cursor));
        let contents = try!(Contents::decode(&mut Decoder::new(json)));
        Ok(contents)
    }

    /// Write `contents` to the file as JSON.
    #[allow(unsafe_code)]
    pub fn write_file<Contents: ::rustc_serialize::Encodable>(&self,
                                                              contents: &Contents)
                                                              -> Result<(), ::error::Error> {
        use memmap::{Mmap, Protection};
        use rustc_serialize::json;
        use std::fs::OpenOptions;
        use std::io::Write;
        let contents = format!("{}", json::as_pretty_json(contents)).into_bytes();
        let file = try!(OpenOptions::new().read(true).write(true).create(true).open(&self.path));
        try!(file.set_len(contents.len() as u64));
        let mut mmap = try!(Mmap::open(&file, Protection::ReadWrite));
        // TODO Replace with facilitites from fs2
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
    let home_dir = try!(::std::env::home_dir().ok_or(io::Error::new(io::ErrorKind::NotFound,
                                                                    "User home directory not \
                                                                     found.")));
    Ok(try!(join_exe_file_stem(&home_dir)).join(".config"))
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
pub fn exe_file_stem() -> Result<OsString, ::error::Error> {
    let exe_path = try!(::std::env::current_exe());
    let file_stem = exe_path.file_stem();
    Ok(try!(file_stem.ok_or(not_found_error(&exe_path))).to_os_string())
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
///         ::crust::FileHandler::new("test.json").unwrap();
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

fn not_found_error(file_name: &Path) -> ::std::io::Error {
    let mut msg: String = From::from("No file name component: ");
    msg.push_str(&file_name.to_string_lossy());
    ::std::io::Error::new(::std::io::ErrorKind::NotFound, msg)
}

fn join_exe_file_stem(path: &::std::path::Path) -> Result<::std::path::PathBuf, ::error::Error> {
    Ok(path.join(try!(exe_file_stem())))
}

#[cfg(test)]
mod test {
    #[test]
    fn read_write_file_test() {
        let _cleaner = super::ScopedUserAppDirRemover;
        let file_handler = unwrap_result!(super::FileHandler::new("file_handler_test.json"));
        let test_value = 123456789u64;

        unwrap_result!(file_handler.write_file::<u64>(&test_value));
        let read_value = unwrap_result!(file_handler.read_file::<u64>());
        assert_eq!(test_value, read_value);
    }
}
