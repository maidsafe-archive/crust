use std::{io, mem};
use std::net::{SocketAddr, SocketAddrV4, IpAddr, Ipv4Addr};
use tokio_core::reactor::Handle;
use tokio_core::net::{UdpSocket, UdpFramed};
use futures::stream::StreamFuture;
use futures::sink;
use futures::{Async, Future, Stream, Sink};
use serde::Serialize;
use serde::de::DeserializeOwned;
use void::Void;

use net::service_discovery::msg::DiscoveryMsg;
use util::SerdeUdpCodec;

pub fn discover<T>(handle: &Handle, port: u16) -> io::Result<Discover<T>>
where
    T: Serialize + DeserializeOwned + Clone + 'static
{

    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
    let socket = UdpSocket::bind(&bind_addr, handle)?;
    socket.set_broadcast(true)?;
    let framed = socket.framed(SerdeUdpCodec::new());

    let request = DiscoveryMsg::Request;
    let broadcast_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), port));
    let writing = framed.send((broadcast_addr, request));

    Ok(Discover {
        state: DiscoverState::Writing { writing },
    })
}

pub struct Discover<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static
{
    state: DiscoverState<T>,
}

enum DiscoverState<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static
{
    Reading {
        reading: StreamFuture<UdpFramed<SerdeUdpCodec<DiscoveryMsg<T>>>>,
    },
    Writing {
        writing: sink::Send<UdpFramed<SerdeUdpCodec<DiscoveryMsg<T>>>>,
    },
    Invalid,
}


impl<T> Stream for Discover<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static
{
    type Item = (Ipv4Addr, T);
    type Error = Void;

    fn poll(&mut self) -> Result<Async<Option<(Ipv4Addr, T)>>, Void> {
        let mut state = mem::replace(&mut self.state, DiscoverState::Invalid);
        let ret = loop {
            match state {
                DiscoverState::Reading { mut reading } => {
                    if let Async::Ready((res, framed)) = unwrap!(reading.poll().map_err(|(e, _)| e)) {
                        state = DiscoverState::Reading { reading: framed.into_future() };
                        match res {
                            Some((addr, Ok(DiscoveryMsg::Response(response)))) => {
                                let ip = match addr.ip() {
                                    IpAddr::V4(ip) => ip,
                                    _ => unreachable!(),
                                };
                                break Async::Ready(Some((ip, response)));
                            },
                            Some((_, Ok(..))) => (),
                            Some((addr, Err(e))) => {
                                warn!("Error deserialising message from {}: {}", addr, e);
                            },
                            None => unreachable!(),
                        }
                    } else {
                        state = DiscoverState::Reading { reading };
                        break Async::NotReady;
                    }
                },
                DiscoverState::Writing { mut writing } => {
                    if let Async::Ready(framed) = unwrap!(writing.poll()) {
                        state = DiscoverState::Reading { reading: framed.into_future() };
                        continue;
                    } else {
                        state = DiscoverState::Writing { writing };
                        break Async::NotReady;
                    }
                },
                DiscoverState::Invalid => panic!(),
            }
        };
        self.state = state;
        Ok(ret)
    }
}

