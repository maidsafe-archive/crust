use std::net::{SocketAddr, UdpSocket};

#[must_use]
pub struct PeriodicSender<D> {
    notify_exit: ::std::sync::mpsc::Sender<()>,
    join_guard: ::crossbeam::ScopedJoinHandle<()>,
    payload_sender: ::std::sync::mpsc::Sender<D>,
    destination_sender: ::std::sync::mpsc::Sender<SocketAddr>,
    //join_guard: ::crossbeam::ScopedJoinHandle<io::Result<()>>,
}

impl<'a, 'b: 'a, D: AsRef<[u8]> + Send + 'b> PeriodicSender<D> {
    pub fn start(
            udp_socket: UdpSocket,
            destination: SocketAddr,
            scope: &::crossbeam::Scope<'a>,
            data: D,
            period_ms: u32
        ) -> PeriodicSender<D>
    {
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
                let _ = udp_socket.send_to(data.as_ref(), destination);
                ::std::thread::park_timeout_ms(period_ms);
                match rx.try_recv() {
                    Err(::std::sync::mpsc::TryRecvError::Empty)        => (),
                    Err(::std::sync::mpsc::TryRecvError::Disconnected) => panic!(),
                    Ok(()) => return,
                }
                match payload_rx.try_recv() {
                    Err(::std::sync::mpsc::TryRecvError::Empty)        => (),
                    Err(::std::sync::mpsc::TryRecvError::Disconnected) => panic!(),
                    Ok(d)  => data = d,
                }
                match destination_rx.try_recv() {
                    Err(::std::sync::mpsc::TryRecvError::Empty)        => (),
                    Err(::std::sync::mpsc::TryRecvError::Disconnected) => panic!(),
                    Ok(a)  => destination = a,
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

    /*
    pub fn stop(self) -> io::Result<()> {
        self.notify_exit.send(());
        self.join_guard.thread().unpark();
        self.join_guard.join()
    }
    */
}

impl<T> Drop for PeriodicSender<T> {
    fn drop(&mut self) {
        self.notify_exit.send(()).unwrap();
        self.join_guard.thread().unpark();
    }
}

