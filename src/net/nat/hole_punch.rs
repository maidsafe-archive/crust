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

use util;
use priv_prelude::*;

/// Punch a hole to a remote peer. Both peers call this simultaneously try to perform a TCP
/// rendezvous connect to each other.
pub fn tcp_hole_punch(
    handle: &Handle,
    socket: TcpBuilder,
    remote_addrs: &[SocketAddr],
) -> io::Result<IoStream<(TcpStream, SocketAddr)>> {
    let mut sockets = Vec::new();
    let local_addr = socket.local_addr()?;
    for addr in remote_addrs {
        let socket = util::new_reusably_bound_tcp_socket(&local_addr)?;
        let socket = socket.to_tcp_stream()?;
        sockets.push((socket, *addr));
    };
    let listener = socket.listen(100)?;
    let listener = TcpListener::from_listener(listener, &local_addr, handle)?;
    let incoming = listener.incoming();

    let connectors = {
        sockets
        .into_iter()
        .map(|(socket, addr)| {
            TcpStream::connect_stream(socket, &addr, handle)
            .map(move |stream| (stream, addr))
        })
        .collect::<Vec<_>>()
    };
    let outgoing = stream::futures_unordered(connectors);
    Ok(outgoing.select(incoming).into_boxed())
}

