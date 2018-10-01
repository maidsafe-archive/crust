// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use maidsafe_utilities::serialisation::{deserialise, serialise_into, SerialisationError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use tokio_core::net::UdpCodec;

#[derive(Debug)]
pub struct SerdeUdpCodec<T> {
    _ph: PhantomData<T>,
}

impl<T> SerdeUdpCodec<T> {
    pub fn new() -> SerdeUdpCodec<T> {
        SerdeUdpCodec { _ph: PhantomData }
    }
}

impl<T> UdpCodec for SerdeUdpCodec<T>
where
    T: Serialize + DeserializeOwned,
{
    type In = (SocketAddr, Result<T, SerialisationError>);
    type Out = (SocketAddr, T);

    fn decode(
        &mut self,
        src: &SocketAddr,
        buf: &[u8],
    ) -> io::Result<(SocketAddr, Result<T, SerialisationError>)> {
        let res = deserialise(buf);
        Ok((*src, res))
    }

    fn encode(&mut self, (addr, data): (SocketAddr, T), buf: &mut Vec<u8>) -> SocketAddr {
        unwrap!(serialise_into(&data, buf));
        addr
    }
}
