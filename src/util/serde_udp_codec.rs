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

use maidsafe_utilities::serialisation::{deserialise, serialise_into, SerialisationError};
use serde::Serialize;
use serde::de::DeserializeOwned;
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
