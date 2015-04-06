extern crate crust;
use std::thread::spawn;

fn fib(n: u64) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        n => fib(n - 1) + fib(n - 2)
    }
}

fn main() {
    // Make a listener on 0.0.0.0:8080
    let (listener, _) = crust::tcp_connections::listen().unwrap();


    // Turn the listener into an iterator of connections.
    for x in listener.iter() {
        let (connection, _) = x;
        // Spawn a new thread for each connection that we get.
        spawn(move || {
            // Upgrade the connection to read `u64` and write `(u64, u64)`.
            let (i, mut o) = crust::tcp_connections::upgrade_tcp(connection).unwrap();
            // For each `u64` that we read from the network...
            for x in i.iter() {
                // Send that number back with the computed value.
                o.send(&(x, fib(x))).ok();
            }
        });
    }
}
