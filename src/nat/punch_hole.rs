// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use mio::tcp::TcpListener;
use nat::{NatError, util};
use net2::TcpBuilder;
use std::net::TcpStream;

pub fn get_sockets(
    mapped_socket: &TcpBuilder,
    required: usize,
) -> Result<(TcpListener, Vec<TcpStream>), NatError> {
    let local_addr = mapped_socket.local_addr()?;
    let mut unconnected_sockets = Vec::with_capacity(required);
    for _ in 0..required {
        let socket = util::new_reusably_bound_tcp_socket(&local_addr)?;
        let socket = socket.to_tcp_stream()?;
        unconnected_sockets.push(socket);
    }

    let listener = mapped_socket.listen(100)?;
    let listener = TcpListener::from_listener(listener, &local_addr)?;

    Ok((listener, unconnected_sockets))
}
