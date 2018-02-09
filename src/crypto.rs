// Copyright 2018 MaidSafe.net limited.
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

use maidsafe_utilities::serialisation::{SerialisationError, deserialise, serialise};
use priv_prelude::*;
use rust_sodium::crypto::box_::{PublicKey, SecretKey};
use secure_serialisation::{Error as SecureSerialiseError, anonymous_deserialise,
                           anonymous_serialise, deserialise as secure_deserialise,
                           serialise as secure_serialise};

quick_error! {
    /// Encryption related errors.
    #[derive(Debug)]
    pub enum CryptoError {
        Serialize(e: SerialisationError) {
            description("Error serializing message")
            display("Error serializing message: {}", e)
            cause(e)
        }
        Deserialize(e: SerialisationError) {
            description("Error deserializing message")
            display("Error deserializing message: {}", e)
            cause(e)
        }
        Encrypt(e: SecureSerialiseError) {
            description("Error encrypting message")
            display("Error encrypting message: {:?}", e)
        }
        Decrypt(e: SecureSerialiseError) {
            description("Error decrypting message")
            display("Error decrypting message: {:?}", e)
        }
        EncryptForbidden {
            description("Encrypt operation is not allowed within this crypto context")
        }
        DecryptForbidden {
            description("Decrypt operation is not allowed within this crypto context")
        }
    }
}

/// Simplifies encryption/decryption by holding the necessary context - encryption keys.
/// Allows "null" encryption where data is only serialized. See: null object pattern.
#[derive(Clone, Debug)]
pub enum CryptoContext {
    Null,
    Authenticated {
        their_pk: PublicKey,
        our_sk: SecretKey,
    },
    AnonymousDecrypt {
        our_pk: PublicKey,
        our_sk: SecretKey,
    },
    AnonymousEncrypt { their_pk: PublicKey },
}

impl CryptoContext {
    pub fn authenticated(their_pk: PublicKey, our_sk: SecretKey) -> Self {
        CryptoContext::Authenticated { their_pk, our_sk }
    }

    /// Contructs "null" encryption context which actually does no encryption.
    /// In this case data is simply serialized but not encrypted.
    pub fn null() -> Self {
        CryptoContext::Null
    }

    /// Constructs crypto context that is only meant for unauthenticated deryption.
    pub fn anonymous_decrypt(our_pk: PublicKey, our_sk: SecretKey) -> Self {
        CryptoContext::AnonymousDecrypt { our_pk, our_sk }
    }

    /// Constructs crypto context that is only meant for unauthenticated encryption.
    pub fn anonymous_encrypt(their_pk: PublicKey) -> Self {
        CryptoContext::AnonymousEncrypt { their_pk }
    }

    pub fn encrypt<T: Serialize>(&self, msg: &T) -> Result<BytesMut, CryptoError> {
        match *self {
            CryptoContext::Null => {
                serialise(msg).map_err(CryptoError::Serialize).map(
                    BytesMut::from,
                )
            }
            CryptoContext::Authenticated {
                ref their_pk,
                ref our_sk,
            } => {
                secure_serialise(msg, their_pk, our_sk)
                    .map_err(CryptoError::Encrypt)
                    .map(BytesMut::from)
            }
            CryptoContext::AnonymousEncrypt { ref their_pk } => {
                anonymous_serialise(msg, their_pk)
                    .map_err(CryptoError::Encrypt)
                    .map(BytesMut::from)
            }
            CryptoContext::AnonymousDecrypt { .. } => Err(CryptoError::DecryptForbidden),
        }
    }

    pub fn decrypt<T>(&self, msg: &[u8]) -> Result<T, CryptoError>
    where
        T: Serialize + DeserializeOwned,
    {
        match *self {
            CryptoContext::Null => deserialise(msg).map_err(CryptoError::Deserialize),
            CryptoContext::Authenticated {
                ref their_pk,
                ref our_sk,
            } => secure_deserialise(msg, their_pk, our_sk).map_err(CryptoError::Decrypt),
            CryptoContext::AnonymousDecrypt {
                ref our_pk,
                ref our_sk,
            } => anonymous_deserialise(msg, our_pk, our_sk).map_err(CryptoError::Decrypt),
            CryptoContext::AnonymousEncrypt { .. } => Err(CryptoError::EncryptForbidden),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod crypto_context {
        use super::*;
        use rust_sodium::crypto::box_::gen_keypair;

        #[test]
        fn when_encryption_is_null_it_serializes_and_deserializes_data() {
            let crypto = CryptoContext::null();

            let encrypted = unwrap!(crypto.encrypt(b"test123"));
            let decrypted: [u8; 7] = unwrap!(crypto.decrypt(&encrypted[..]));

            assert_eq!(&decrypted, b"test123");
        }

        #[test]
        fn when_encryption_keys_are_given_it_encrypts_and_decrypts_data_with_them() {
            let (pk1, sk1) = gen_keypair();
            let (pk2, sk2) = gen_keypair();
            let crypto1 = CryptoContext::authenticated(pk2, sk1);
            let crypto2 = CryptoContext::authenticated(pk1, sk2);

            let encrypted = unwrap!(crypto1.encrypt(b"test123"));
            let decrypted: [u8; 7] = unwrap!(crypto2.decrypt(&encrypted[..]));

            assert_eq!(&decrypted, b"test123");
        }

        #[test]
        fn anonymous_encryption() {
            let (pk2, sk2) = gen_keypair();
            let crypto1 = CryptoContext::anonymous_encrypt(pk2);
            let crypto2 = CryptoContext::anonymous_decrypt(pk2, sk2);

            let encrypted = unwrap!(crypto1.encrypt(b"test123"));
            let decrypted: [u8; 7] = unwrap!(crypto2.decrypt(&encrypted[..]));

            assert_eq!(&decrypted, b"test123");
        }
    }
}
