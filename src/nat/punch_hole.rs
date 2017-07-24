// Copyright 2016 MaidSafe.net limited.
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
