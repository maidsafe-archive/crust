use std::time::{Duration, Instant};
use tokio_core::reactor::Handle;
use futures::Future;

use util::with_timeout::WithTimeout;

pub trait FutureExt: Future {
    fn with_timeout(self, handle: &Handle, duration: Duration, error: Self::Error) -> WithTimeout<Self>
    where
        Self: Sized
    {
        WithTimeout::new(handle, self, duration, error)
    }

    fn with_timeout_at(self, handle: &Handle, at: Instant, error: Self::Error) -> WithTimeout<Self>
    where
        Self: Sized
    {
        WithTimeout::new_at(handle, self, at, error)
    }
}

impl<F> FutureExt for F
where F: Future
{
}

