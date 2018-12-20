// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::common::Core;
use mio::{Poll, Ready};
use std::any::Any;

use socket_collection::Priority;

pub trait State<T> {
    fn as_any(&mut self) -> &mut Any;

    fn ready(&mut self, _core: &mut Core<T>, _poll: &Poll, _kind: Ready) {}

    fn terminate(&mut self, _core: &mut Core<T>, _poll: &Poll) {}

    fn timeout(&mut self, _core: &mut Core<T>, _poll: &Poll, _timer_id: u8) {}

    fn write(&mut self, _core: &mut Core<T>, _poll: &Poll, _data: Vec<u8>, _priority: Priority) {}
}
