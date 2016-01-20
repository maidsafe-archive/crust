// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::net::UdpSocket;
use config_file_handler::socket_addr::SocketAddr;

#[must_use]
pub struct PeriodicSender<D> {
    notify_exit: ::std::sync::mpsc::Sender<()>,
    join_guard: ::crossbeam::ScopedJoinHandle<()>,
    payload_sender: ::std::sync::mpsc::Sender<D>,
    destination_sender: ::std::sync::mpsc::Sender<SocketAddr>, /* join_guard: ::crossbeam::ScopedJoinHandle<io::Result<()>>, */
}

impl<'a, 'b: 'a, D: AsRef<[u8]> + Send + 'b> PeriodicSender<D> {
    pub fn start(udp_socket: UdpSocket,
                 destination: SocketAddr,
                 scope: &::crossbeam::Scope<'a>,
                 data: D,
                 period: ::std::time::Duration)
                 -> PeriodicSender<D> {
        let (tx, rx) = ::std::sync::mpsc::channel::<()>();
        let (payload_tx, payload_rx) = ::std::sync::mpsc::channel::<D>();
        let (destination_tx, destination_rx) = ::std::sync::mpsc::channel::<SocketAddr>();
        let join_guard = scope.spawn(move || {
            let mut data = data;
            let mut destination = destination;
            loop {
                // TODO (canndrew): Will be possible to extract this error through `stop()`
                // once the rust guys implement linear types/disableable drop.
                // see: https://github.com/rust-lang/rfcs/issues/523
                // see: https://github.com/rust-lang/rfcs/issues/814
                let _ = udp_socket.send_to(data.as_ref(), &*destination);
                ::std::thread::park_timeout(period);
                match rx.try_recv() {
                    Err(::std::sync::mpsc::TryRecvError::Empty) => (),
                    Err(::std::sync::mpsc::TryRecvError::Disconnected) => panic!(),
                    Ok(()) => return,
                }
                match payload_rx.try_recv() {
                    Err(::std::sync::mpsc::TryRecvError::Empty) => (),
                    Err(::std::sync::mpsc::TryRecvError::Disconnected) => panic!(),
                    Ok(d) => data = d,
                }
                match destination_rx.try_recv() {
                    Err(::std::sync::mpsc::TryRecvError::Empty) => (),
                    Err(::std::sync::mpsc::TryRecvError::Disconnected) => panic!(),
                    Ok(a) => destination = a,
                }
            }
        });
        PeriodicSender {
            notify_exit: tx,
            join_guard: join_guard,
            payload_sender: payload_tx,
            destination_sender: destination_tx,
        }
    }

    pub fn set_payload(&self, data: D) {
        // ignore this error, indicates that the sending thread has died
        let _ = self.payload_sender.send(data);
    }

    pub fn set_destination(&self, destination: SocketAddr) {
        // ignore this error, indicates that the sending thread has died
        let _ = self.destination_sender.send(destination);
    }

    // pub fn stop(self) -> io::Result<()> {
    // self.notify_exit.send(());
    // self.join_guard.thread().unpark();
    // self.join_guard.join()
    // }
    //
}

impl<T> Drop for PeriodicSender<T> {
    fn drop(&mut self) {
        self.notify_exit.send(()).unwrap();
        self.join_guard.thread().unpark();
    }
}
