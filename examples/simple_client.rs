extern crate crust;
use std::str::FromStr;



fn main() {
    // incoming: (u64, u64)
    // outgoing: u64
    let (i, mut o) = crust::tcp_connections::connect_tcp(std::net::SocketAddr::from_str("127.0.0.1:5483").unwrap()).unwrap();

    // Send all the numbers from 0 to 10.
    for x in (0u64..10u64) {
        o.send(&x).ok();
    }

    // Close our outgoing pipe. This is necessary because otherwise,
    // the server will keep waiting for the client to send it data and
    // we will deadlock.
    o.close();

    // Print everything that we get back.
    for a in i.iter() {
        let (x, fx): (u64, u64) = a;
        println!("{} -> {}", x, fx);
    }
}
