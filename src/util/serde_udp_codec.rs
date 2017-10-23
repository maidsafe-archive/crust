use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use tokio_core::net::UdpCodec;
use maidsafe_utilities::serialisation::{SerialisationError, serialise_into, deserialise};
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Debug)]
pub struct SerdeUdpCodec<T> {
    _ph: PhantomData<T>,
}

impl<T> SerdeUdpCodec<T> {
    pub fn new() -> SerdeUdpCodec<T> {
        SerdeUdpCodec {
            _ph: PhantomData,
        }
    }
}

impl<T> UdpCodec for SerdeUdpCodec<T>
where
    T: Serialize + DeserializeOwned
{
    type In = (SocketAddr, Result<T, SerialisationError>);
    type Out = (SocketAddr, T);

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<(SocketAddr, Result<T, SerialisationError>)> {
        let res = deserialise(buf);
        Ok((*src, res))
    }

    fn encode(&mut self, (addr, data): (SocketAddr, T), buf: &mut Vec<u8>) -> SocketAddr {
        unwrap!(serialise_into(&data, buf));
        addr
    }
}


