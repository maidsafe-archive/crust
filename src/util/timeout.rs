// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! tokio timeouts cannot actually error, but for some stupid reason tokio decided to put an io
//! error on them. This is just a wrapper which removes the error and makes error handling easier
//! when using timeouts.

use futures::{Async, Future};
use std::io;
use std::time::{Duration, Instant};
use tokio_core;
use tokio_core::reactor::Handle;
use void::Void;

pub struct Timeout {
    inner: tokio_core::reactor::Timeout,
}

impl Timeout {
    pub fn new(duration: Duration, handle: &Handle) -> io::Result<Timeout> {
        Ok(Timeout {
            inner: tokio_core::reactor::Timeout::new(duration, handle)?,
        })
    }

    pub fn new_at(at: Instant, handle: &Handle) -> io::Result<Timeout> {
        Ok(Timeout {
            inner: tokio_core::reactor::Timeout::new_at(at, handle)?,
        })
    }

    pub fn reset(&mut self, at: Instant) {
        self.inner.reset(at)
    }
}

impl Future for Timeout {
    type Item = ();
    type Error = Void;

    fn poll(&mut self) -> Result<Async<()>, Void> {
        Ok(unwrap!(self.inner.poll()))
    }
}
