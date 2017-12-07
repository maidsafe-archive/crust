// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use priv_prelude::*;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BootstrapRequest<UID> {
    pub uid: UID,
    pub name_hash: NameHash,
    pub ext_reachability: ExternalReachability,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConnectRequest<UID> {
    pub uid: UID,
    pub name_hash: NameHash,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HandshakeMessageType<UID> {
    BootstrapRequest(BootstrapRequest<UID>),
    BootstrapGranted(UID),
    BootstrapDenied(BootstrapDenyReason),
    ChooseConnection,
    Connect(ConnectRequest<UID>),
}

/// Same as `HandshakeMessageType`, except it also appends special 8 byte header to every
/// type of handshake message when serialized.
/// `HandshakeMessage` should be used to send and deserialized received messages.
/// `HandshakeMessageType` is supposed to used for received message type matching.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HandshakeMessage<UID> {
    header: [u8; 8],
    type_: HandshakeMessageType<UID>,
}

impl<UID: Uid> HandshakeMessage<UID> {
    fn new(type_: HandshakeMessageType<UID>) -> HandshakeMessage<UID> {
        HandshakeMessage {
            header: [
                'C' as u8,
                'R' as u8,
                'U' as u8,
                'S' as u8,
                'T' as u8,
                0,
                0,
                0,
            ],
            type_,
        }
    }

    pub fn bootstrap_request(req: BootstrapRequest<UID>) -> HandshakeMessage<UID> {
        HandshakeMessage::new(HandshakeMessageType::BootstrapRequest(req))
    }

    pub fn bootstrap_granted(peer_id: UID) -> HandshakeMessage<UID> {
        HandshakeMessage::new(HandshakeMessageType::BootstrapGranted(peer_id))
    }

    pub fn bootstrap_denied(reason: BootstrapDenyReason) -> HandshakeMessage<UID> {
        HandshakeMessage::new(HandshakeMessageType::BootstrapDenied(reason))
    }

    pub fn choose_connection() -> HandshakeMessage<UID> {
        HandshakeMessage::new(HandshakeMessageType::ChooseConnection)
    }

    pub fn connec_request(req: ConnectRequest<UID>) -> HandshakeMessage<UID> {
        HandshakeMessage::new(HandshakeMessageType::Connect(req))
    }

    pub fn msg_type(&self) -> HandshakeMessageType<UID> {
        self.type_.clone()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BootstrapDenyReason {
    InvalidNameHash,
    FailedExternalReachability,
    NodeNotWhitelisted,
    ClientNotWhitelisted,
}
