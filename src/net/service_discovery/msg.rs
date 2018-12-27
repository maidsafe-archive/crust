// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::priv_prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMsg {
    /// Request has sender's public key which should be used to encrypt response.
    Request(PublicEncryptKey),
    /// Response comes serialized and encrypted.
    Response(BytesMut),
}
