use std::net::{SocketAddr, UdpSocket};

#[must_use]
pub struct PeriodicSender {
    notify_exit: ::std::sync::mpsc::Sender<()>,
    join_guard: ::crossbeam::ScopedJoinHandle<()>,
    //join_guard: ::crossbeam::ScopedJoinHandle<io::Result<()>>,
}

impl PeriodicSender {
    pub fn start<'a, 'b: 'a>(
            udp_socket: UdpSocket,
            destinations: &'b [SocketAddr],
            scope: &::crossbeam::Scope<'a>,
            data: &'b [u8],
            period_ms: u32
        ) -> PeriodicSender
    {
        let (tx, rx) = ::std::sync::mpsc::channel::<()>();
        let join_guard = scope.spawn(move || {
            loop {
                for dest in destinations.iter() {
                    // TODO (canndrew): Will be possible to extract this error through `stop()`
                    // once the rust guys implement linear types/disableable drop.
                    // see: https://github.com/rust-lang/rfcs/issues/523
                    // see: https://github.com/rust-lang/rfcs/issues/814
                    let _ = udp_socket.send_to(data, dest);
                };
                ::std::thread::park_timeout_ms(period_ms);
                match rx.try_recv() {
                    Err(::std::sync::mpsc::TryRecvError::Empty)        => (),
                    Err(::std::sync::mpsc::TryRecvError::Disconnected) => panic!(),
                    Ok(()) => return,
                }
            }
        });
        PeriodicSender {
            notify_exit: tx,
            join_guard: join_guard,
        }
    }

    /*
    pub fn stop(self) -> io::Result<()> {
        self.notify_exit.send(());
        self.join_guard.thread().unpark();
        self.join_guard.join()
    }
    */
}

impl Drop for PeriodicSender {
    fn drop(&mut self) {
        self.notify_exit.send(()).unwrap();
        self.join_guard.thread().unpark();
    }
}

