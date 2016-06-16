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
// Defines `Core`, the mio handler and the core of the event loop.

pub use self::error::CommonError;
pub use self::core::{Context, Core, CoreMessage};
pub use self::message::Message;
pub use self::socket::Socket;
pub use self::state::State;

// Priority of a message to be sent by Crust. Priority 0 being the highest and will _not_ be
// dropped. Priority 255 is hence the least important and will be preempted/dropped if need be to
// allow higher priority messages through.
pub type Priority = u8;
pub type NameHash = u64;
pub type Result<T> = ::std::result::Result<T, CommonError>;

mod core;
mod error;
mod message;
mod socket;
mod state;
pub mod socket_addr;

