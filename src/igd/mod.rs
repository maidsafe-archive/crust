#[allow(unused)]
mod errors;
mod gateway;
mod search;
mod http_request;
mod utils;
mod soap;

pub use igd::gateway::Gateway;
pub use igd::errors::{SearchError, GetExternalIpError, AddAnyPortError};
pub use igd::search::{search_gateway_from, search_gateway};

#[cfg(test)]
mod tests {
    use core::Core;
    use mio::EventLoop;
    use super::*;

    #[test]
    fn foobar() {
        let mut event_loop = EventLoop::new().unwrap();
        let mut core = Core::new();
        search_gateway(&mut core, &mut event_loop, |res, core, event_loop| {
            println!("Hello World {:?}", res);
            if let Ok(gateway) = res {
                gateway.get_external_ip(core, event_loop, |res, _, _| {
                    println!("Goodbye world {:?}", res);
                });
            }
        });
        event_loop.run(&mut core).expect("EventLoop failed to run");
    }
}
