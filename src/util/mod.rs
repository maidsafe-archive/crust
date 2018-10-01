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
