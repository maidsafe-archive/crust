// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use common::Core;
use mio::{Poll, Ready};
use std::any::Any;

pub type Priority = u8;

pub trait State {
    fn as_any(&mut self) -> &mut Any;

    fn ready(&mut self, _core: &mut Core, _poll: &Poll, _kind: Ready) {}

    fn terminate(&mut self, _core: &mut Core, _poll: &Poll) {}

    fn timeout(&mut self, _core: &mut Core, _poll: &Poll, _timer_id: u8) {}

    fn write(&mut self, _core: &mut Core, _poll: &Poll, _data: Vec<u8>, _priority: Priority) {}
}
