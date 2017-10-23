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



