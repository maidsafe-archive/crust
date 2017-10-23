//! tokio timeouts cannot actually error, but for some stupid reason tokio decided to put an io
//! error on them. This is just a wrapper which removes the error and makes error handling easier
//! when using timeouts.

use std::io;
use std::time::{Duration, Instant};
use futures::{Async, Future};
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

