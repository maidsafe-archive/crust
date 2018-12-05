// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! mio extensions

#[cfg(unix)]
use mio::unix::UnixReady;
use mio::Ready;
#[cfg(unix)]
use std::convert::Into;

/// Some helpful cross platform methods for mio `Ready`.
pub trait MioReadyExt {
    /// Sets error and HUP readiness.
    /// On Windows returns empty `Ready` set.
    fn error_and_hup() -> Ready;

    /// Checks if readiness has error or HUP flags.
    fn is_error_or_hup(&self) -> bool;
}

impl MioReadyExt for Ready {
    #[cfg(unix)]
    fn error_and_hup() -> Ready {
        // UnixReady is converted to Ready
        (UnixReady::error() | UnixReady::hup()).into()
    }

    #[cfg(not(unix))]
    fn error_and_hup() -> Ready {
        Ready::empty()
    }

    #[cfg(unix)]
    fn is_error_or_hup(&self) -> bool {
        let ready: UnixReady = (*self).into();
        ready.is_error() | ready.is_hup()
    }

    #[cfg(not(unix))]
    fn is_error_or_hup(&self) -> bool {
        false
    }
}
