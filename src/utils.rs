use std::path::{Path, PathBuf};
use std::io::Error as IoError;
use std::env::VarError;

pub enum Error {
    EnvError(VarError),
    IoError(IoError),
}

impl From<VarError> for Error {
    fn from(e: VarError) -> Self {
        Error::EnvError(e)
    }
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::IoError(e)
    }
}

fn not_found_error() -> IoError {
    use std::io::ErrorKind as IoErrorKind;
    IoError::new(IoErrorKind::NotFound, "No file name component")
}

#[allow(dead_code)]
fn join_exe_name(path: &Path) -> Result<PathBuf, Error> {
    use std::env;
    let exe_path = try!(env::current_exe());
    let exe_name = try!(exe_path.file_name().ok_or(not_found_error()));
    Ok(path.join(exe_name))
}

#[cfg(target_os="windows")]
pub fn user_app_dir() -> Result<PathBuf, Error> {
    use std::env;
    Ok(try!(join_exe_name(Path::new(&try!(env::var("APPDATA"))))))
}

#[cfg(any(target_os="macos",target_os="ios"))]
pub fn user_app_dir() -> Result<PathBuf, Error> {
    use std::env;
    Ok(try!(join_exe_name(&try!(env::home_dir().ok_or(not_found_error()))
                          .join("Library").join("Application Support"))))
}

#[cfg(target_os="linux")]
pub fn user_app_dir() -> Result<PathBuf, Error> {
    use std::env;
    Ok(try!(join_exe_name(&try!(env::home_dir().ok_or(not_found_error()))
                          .join(".config"))))
}

#[cfg(target_os="windows")]
pub fn system_app_support_dir() -> Result<PathBuf, Error> {
    use std::env;
    Ok(try!(join_exe_name(Path::new(&try!(env::var("ALLUSERSPROFILE"))))))
}

#[cfg(any(target_os="macos",target_os="ios"))]
pub fn system_app_support_dir() -> Result<PathBuf, Error> {
    join_exe_name(Path::new("/Library/Application Support"))
}

#[cfg(target_os="linux")]
pub fn system_app_support_dir() -> Result<PathBuf, Error> {
    join_exe_name(Path::new("/var/lib"))
}
