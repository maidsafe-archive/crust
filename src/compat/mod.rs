//! This module is a backwards-compatibility layer which implements the old message-passing-based
//! API on top of the new futures API.

use maidsafe_utilities;

pub use self::event::{Event, ConnectionInfoResult};
pub use self::service::Service;
pub use self::event_loop::EventLoop;
pub use self::connection_map::ConnectionMap;

mod event;
mod service;
mod event_loop;
mod connection_map;

/// Used to receive events from a `Service`.
pub type CrustEventSender<UID> = maidsafe_utilities::event_sender::MaidSafeObserver<Event<UID>>;

