#[allow(unused)]
mod errors;
mod gateway;
mod search;
mod http_request;
mod utils;
mod soap;

pub use igd::gateway::{Gateway, PortMappingProtocol};
pub use igd::errors::{SearchError, GetExternalIpError, AddAnyPortError};
pub use igd::search::{search_gateway_from, search_gateway};
