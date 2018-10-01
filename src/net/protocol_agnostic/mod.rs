// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub use self::addr::PaAddr;
pub use self::listener::{AcceptError, PaIncoming, PaListener};
pub use self::query::{PaTcpAddrQuerier, PaUdpAddrQuerier};
pub use self::stream::{
    DirectConnectError, PaRendezvousConnectError, PaRendezvousMsg, PaStream, PaStreamReadError,
    PaStreamWriteError, UtpRendezvousConnectError,
};
use priv_prelude::*;

#[macro_use]
mod addr;
mod listener;
mod query;
mod stream;

#[derive(Debug, Serialize, Deserialize)]
struct ListenerMsg {
    client_pk: PublicEncryptKey,
    kind: ListenerMsgKind,
}

#[derive(Debug, Serialize, Deserialize)]
enum ListenerMsgKind {
    EchoAddr,
    Connect,
}
