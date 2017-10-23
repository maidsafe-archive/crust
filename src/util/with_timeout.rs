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

use std::time::{Duration, Instant};
use futures::{Async, Future};
use tokio_core::reactor::{Handle, Timeout};

pub struct WithTimeout<F>
where
    F: Future,
{
    future: F,
    timeout: Timeout,
    error: Option<F::Error>,
}

impl<F> WithTimeout<F>
where
    F: Future,
{
    pub fn new(handle: &Handle, future: F, duration: Duration, error: F::Error) -> WithTimeout<F> {
        WithTimeout {
            future: future,
            timeout: unwrap!(Timeout::new(duration, handle)),
            error: Some(error),
        }
    }

    pub fn new_at(handle: &Handle, future: F, at: Instant, error: F::Error) -> WithTimeout<F> {
        WithTimeout {
            future: future,
            timeout: unwrap!(Timeout::new_at(at, handle)),
            error: Some(error),
        }
    }
}

impl<F> Future for WithTimeout<F>
where
    F: Future
{
    type Item = F::Item;
    type Error = F::Error;

    fn poll(&mut self) -> Result<Async<F::Item>, F::Error> {
        match self.timeout.poll() {
            Ok(Async::Ready(())) => return Err(unwrap!(self.error.take())),
            Ok(Async::NotReady) => (),
            Err(..) => unreachable!(),
        };

        self.future.poll()
    }
}



