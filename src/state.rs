// Copyright 2016 MaidSafe.net limited.
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

use std::any::Any;

use core::Core;
use mio::{Handler, EventLoop, EventSet, Token};

pub trait State {
    fn execute(&mut self,
               _core: &mut Core,
               _event_loop: &mut EventLoop<Core>,
               _token: Token,
               _event_set: EventSet) {
    }

    fn ready(&mut self,
             _core: &mut Core,
             _event_loop: &mut EventLoop<Core>,
             _token: Token,
             _event_set: EventSet) {
    }

    fn terminate(&mut self, _core: &mut Core, _event_loop: &mut EventLoop<Core>) {}

    fn timeout(&mut self,
               _core: &mut Core,
               _event_loop: &mut EventLoop<Core>,
               _timeout: <Core as Handler>::Timeout) {
    }

    fn write(&mut self, _core: &mut Core, _event_loop: &mut EventLoop<Core>, _data: Vec<u8>) {}

    fn as_any(&mut self) -> &mut Any;
}
