// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod ip_addr;
#[cfg(test)]
pub mod memstream;
mod serde_udp_codec;

pub use self::ip_addr::*;
pub use self::serde_udp_codec::SerdeUdpCodec;

#[cfg(test)]
mod test;

#[cfg(test)]
pub use self::test::*;

#[cfg(feature = "connections_info")]
use priv_prelude::*;

/// Tries given expression. Returns boxed future error on failure.
// NOTE: it is duplicate with the one in p2p crate. Consider reusing.
macro_rules! try_bfut {
    ($e:expr) => {
        match $e {
            Ok(t) => t,
            Err(e) => return future::err(e).into_boxed(),
        }
    };
}

#[cfg(feature = "connections_info")]
pub trait ConsumedStream: Stream + Sized {
    /// Runs the provided callback when the stream finishes.
    fn when_consumed<F>(self, callback: F) -> Consumed<Self, F>
    where
        F: FnOnce(),
    {
        Consumed::new(self, callback)
    }
}

#[cfg(feature = "connections_info")]
impl<T: Stream + Sized> ConsumedStream for T {}

#[cfg(feature = "connections_info")]
pub struct Consumed<S, F>
where
    S: Stream,
    F: FnOnce(),
{
    inner: S,
    callback: Option<F>,
}

#[cfg(feature = "connections_info")]
impl<S, F> Consumed<S, F>
where
    S: Stream,
    F: FnOnce(),
{
    pub fn new(inner: S, callback: F) -> Self {
        Self {
            inner,
            callback: Some(callback),
        }
    }
}

#[cfg(feature = "connections_info")]
impl<S, F> Stream for Consumed<S, F>
where
    S: Stream,
    F: FnOnce(),
{
    type Item = S::Item;
    type Error = S::Error;

    fn poll(&mut self) -> Result<Async<Option<S::Item>>, S::Error> {
        match self.inner.poll()? {
            Async::Ready(None) => {
                unwrap!(self.callback.take())();
                Ok(Async::Ready(None))
            }
            Async::Ready(Some(item)) => Ok(Async::Ready(Some(item))),
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}
