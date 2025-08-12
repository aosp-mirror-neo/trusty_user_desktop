/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Cryptographic operations used by the finger guard service.

use crate::aidl::ExportToAidl;
use crate::error::{ServiceError, ServiceResult};
use crate::hat::SignedHat;
use crate::identifiers::SensorStateIndex;
use crate::rng;
use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::{
    AuthenticationResult::AuthenticationResult,
    FinishEnrollSessionResponse::FinishEnrollSessionResponse, HandshakeResponse::HandshakeResponse,
    PrepareAuthSessionResponse::PrepareAuthSessionResponse,
    PrepareEnrollSessionResponse::PrepareEnrollSessionResponse, SessionResponse::SessionResponse,
};
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hmac::HmacCtx;
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::symm::Cipher;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Extend Result with a function that can map openssl errors to service errors.
pub trait MapOpenSslErrExt<T> {
    /// Transform Self (a result with an openssl error type) into a ServiceResult with the given
    /// error message.
    fn wrap_openssl_err(self, msg: &'static str) -> ServiceResult<T>;
}
impl<T> MapOpenSslErrExt<T> for Result<T, openssl::error::ErrorStack> {
    fn wrap_openssl_err(self, msg: &'static str) -> ServiceResult<T> {
        self.map_err(|e| ServiceError::OpenSsl(msg, Box::new(e)))
    }
}

/// Create a type to represent a fixed-size chunk of binary data.
///
/// These types are used to represent various secure blobs of data such as keys and nonces and
/// hashes. The reason for using these stronger types is to avoid accidental misuse of the raw
/// bytes, for example by forcing the use of constant-time comparison.
///
/// The generated type will have the following properties:
///   - A const SIZE member, the size of the blob in bytes
///   - Support for (safe constant-time) equality comparisons with the same type
///
/// In order to be useful for serialization to storage the generated type will also support the
/// From and Into bytes traits from zerocopy. However, these traits should not be used directly
/// by internal code to extract the raw bytes. Any operations that need to use the bytes should
/// instead be defined on the generated type directly.
macro_rules! blob_newtype {
    ($name:ident, $size:literal) => {
        /// A binary blob of representing a cryptographic object.
        #[derive(FromBytes, IntoBytes, Immutable)]
        pub struct $name {
            bytes: [u8; $size],
        }
        impl PartialEq<&[u8]> for $name {
            fn eq(&self, other: &&[u8]) -> bool {
                openssl::memcmp::eq(&self.bytes, other)
            }
        }
        impl $name {
            #[allow(dead_code)] // This is not necessarily used on every type.
            const SIZE: usize = $size;
        }
    };
}

// Define a type for a generic key.
blob_newtype!(Key, 32);

// Define a new type for nonces.
blob_newtype!(Nonce, 32);
impl Nonce {
    /// Securely generate a new nonce.
    pub fn generate() -> Self {
        Self { bytes: rng::generate_random_buffer::<{ Self::SIZE }>() }
    }
    /// Import a nonce that was supplied as a blob of bytes. Can fail if the size is incorrect.
    pub fn import(value: &[u8]) -> ServiceResult<Self> {
        Ok(Self {
            bytes: value.try_into().map_err(|_| ServiceError::BufferSizeMismatch {
                name: "nonce",
                expected: Nonce::SIZE,
                actual: value.len(),
            })?,
        })
    }
}
impl ExportToAidl<SessionResponse> for Nonce {
    fn export(&self, out: &mut SessionResponse) {
        out.nonce = self.bytes.to_vec();
    }
}
impl ExportToAidl<PrepareAuthSessionResponse> for Nonce {
    fn export(&self, out: &mut PrepareAuthSessionResponse) {
        out.nonce = self.bytes;
    }
}
impl HmacSignable for Nonce {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        add_bytes(&self.bytes)
    }
}

// Define a new type for a secret. Note that while most of the blobs (e.g. nonces, keys) are
// secrets, those ones have additional semantic intent: nonces should only be used once, keys
// can be used to encrypt/decrypt data, and so on.
blob_newtype!(Secret, 32);
impl Secret {
    /// Securely generate a new secret.
    pub fn generate() -> Self {
        Self { bytes: rng::generate_random_buffer::<{ Self::SIZE }>() }
    }
}

/// The type of EC used by finger_guard.
pub const NIST_P256_CURVE_NAME: Nid = Nid::X9_62_PRIME256V1;

/// Generate a new EC private key.
pub fn ec_keygen() -> Result<EcKey<Private>, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
    let server_private_key = EcKey::generate(&group)?;
    Ok(server_private_key)
}

/// Serialize a given EC private key into a blob of bytes.
pub fn ec_public_key_serialization(
    private_key: &EcKey<Private>,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
    let mut ctx = BigNumContext::new()?;
    let server_public_key_bytes =
        private_key.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    Ok(server_public_key_bytes)
}

/// Perform a DH exchange using a private and public key, returning the new private key.
pub fn perform_ecdh(
    server_private_key: EcKey<Private>,
    client_public_key_bytes: &[u8],
) -> ServiceResult<Key> {
    // Perform all of the crypto operations to produce the new key.
    let pk = (|| {
        let server_private_key: PKey<Private> = server_private_key.try_into()?;
        let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
        let mut ctx = BigNumContext::new()?;
        let client_public_point = EcPoint::from_bytes(&group, client_public_key_bytes, &mut ctx)?;
        let client_public_key: PKey<Public> =
            EcKey::from_public_key(&group, &client_public_point)?.try_into()?;
        let mut pk_deriver = Deriver::new(&server_private_key)?;
        pk_deriver.set_peer(&client_public_key)?;
        let pk = pk_deriver.derive_to_vec()?;
        Ok(pk)
    })()
    .wrap_openssl_err("failed to derive pk")?;
    // Convert the resulting key object into a Key instance.
    let len = pk.len();
    Ok(Key {
        bytes: pk.try_into().map_err(|_| ServiceError::BufferSizeMismatch {
            name: "pk",
            expected: Key::SIZE,
            actual: len,
        })?,
    })
}

/// Encrypt a message using AES256-GCM with the given Hmac as a key.
pub fn encrypt_aes256_gcm(
    key: &Hmac,
    iv: &[u8],
    aad: &[u8],
    data: &Secret,
    tag: &mut [u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    openssl::symm::encrypt_aead(
        Cipher::aes_256_gcm(),
        key.bytes.as_slice(),
        Some(iv),
        aad,
        &data.bytes,
        tag,
    )
}

/// Decrypt a message using AES256-GCM with the given Hmac as a key.
pub fn decrypt_aes256_gcm(
    key: &Hmac,
    iv: &[u8],
    aad: &[u8],
    data: &[u8],
    tag: &[u8],
) -> ServiceResult<Secret> {
    let secret = openssl::symm::decrypt_aead(
        Cipher::aes_256_gcm(),
        key.bytes.as_slice(),
        Some(iv),
        aad,
        data,
        tag,
    )
    .wrap_openssl_err("decryption operation failed")?;
    let len = secret.len();
    Ok(Secret {
        bytes: secret.try_into().map_err(|_| ServiceError::BufferSizeMismatch {
            name: "secret",
            expected: Secret::SIZE,
            actual: len,
        })?,
    })
}

/// The sender of a message.
pub enum MessageSender {
    /// The sender was the finger_guard service.
    FingerGuard,
    /// The sender was the FPMCU.
    Fpmcu,
}
impl HmacSignable for MessageSender {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        let name: &[u8] = match self {
            MessageSender::FingerGuard => b"finger_guard",
            MessageSender::Fpmcu => b"fpmcu",
        };
        add_bytes(name)
    }
}

/// The operation this session is performing.
pub enum SensorSessionType {
    /// Start fingerprint enrollment.
    Enroll,
    /// Complete fingerprint enrollment.
    EnrollFinish,
    /// Authenticate using fingerprint.
    Auth,
}
impl HmacSignable for SensorSessionType {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        let name: &[u8] = match self {
            SensorSessionType::Enroll => b"enroll",
            SensorSessionType::EnrollFinish => b"enroll_finish",
            SensorSessionType::Auth => b"auth",
        };
        add_bytes(name)
    }
}

// Define a type for a the SHA-256 HMACs we use.
blob_newtype!(Hmac, 32);
// HMACs can also be used as keys, so we support Hmac->Key conversion.
impl From<Hmac> for Key {
    fn from(value: Hmac) -> Self {
        Self { bytes: value.bytes }
    }
}
// HMACs can also be reported as an authentication result.
impl From<Hmac> for AuthenticationResult {
    fn from(value: Hmac) -> Self {
        // An HMAC is only provided on a successful authentication, so the authenticated bit is
        // assumed to be true if you're constructing a result from an HMAC.
        Self { authenticated: true, mac: value.bytes.to_vec() }
    }
}
impl ExportToAidl<SignedHat> for Hmac {
    fn export(&self, out: &mut SignedHat) {
        out.mac = self.bytes.to_vec();
    }
}
impl ExportToAidl<HandshakeResponse> for Hmac {
    fn export(&self, out: &mut HandshakeResponse) {
        out.pkMac = self.bytes.to_vec();
    }
}
impl ExportToAidl<PrepareAuthSessionResponse> for Hmac {
    fn export(&self, out: &mut PrepareAuthSessionResponse) {
        out.mac = self.bytes.to_vec();
    }
}
impl ExportToAidl<PrepareEnrollSessionResponse> for Hmac {
    fn export(&self, out: &mut PrepareEnrollSessionResponse) {
        out.mac = self.bytes.to_vec();
    }
}
impl ExportToAidl<FinishEnrollSessionResponse> for Hmac {
    fn export(&self, out: &mut FinishEnrollSessionResponse) {
        out.mac = self.bytes.to_vec();
    }
}

/// Generator which can consume bytes and produce an HMAC.
///
/// The HMACs used by finger guard are based on SHA-256 hashes.
pub struct HmacGenerator {
    context: HmacCtx,
}

/// Trait which types can implement to support being used as part of a signed message.
pub trait HmacSignable {
    /// Update the HMAC with the relevant bytes from Self.
    fn update(&self, add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()>;
}

impl HmacGenerator {
    /// Construct a new HMAC generator that will use the given key.
    pub fn new(key: &Key) -> ServiceResult<Self> {
        Ok(Self {
            context: HmacCtx::new(&key.bytes, Md::sha256())
                .wrap_openssl_err("unable to initialize hmac")?,
        })
    }

    /// Update the HMAC with the given signable object.
    pub fn update(&mut self, signable: &impl HmacSignable) -> ServiceResult<()> {
        signable
            .update(|bytes| self.context.update(bytes).wrap_openssl_err("unable to update hmac"))
    }

    /// Complete the generation of the HMAC, returning the final result.
    pub fn complete(mut self) -> ServiceResult<Hmac> {
        let mut hmac = Hmac { bytes: Default::default() };
        self.context
            .finalize(hmac.bytes.as_mut_slice())
            .wrap_openssl_err("unable to finalize hmac")?;
        Ok(hmac)
    }
}

/// Macro which computes an HMAC from a number of HMAC signables.
///
/// This is a convenience wrapper that does a "new + update*N + complete" call but in a single
/// compact invocation. This behaves like a function but unlike a function it takes a variable
/// number of arguments.
#[macro_export]
macro_rules! _compute_hmac {
    ($key:expr, $($signable:expr),*) => {
        (|| {
            let mut generator = $crate::crypto::HmacGenerator::new($key)?;
            $(generator.update($signable)?;)*
            generator.complete()
        })()
    }
}
pub use _compute_hmac as compute_hmac;

/// Helper to compute the HMAC for the enrollment/authentication
/// session messages from this service or from the sensor.
pub fn sensor_session_message_hmac(
    key: &Key,
    nonce: &Nonce,
    sender: MessageSender,
    session_type: SensorSessionType,
    ssi: &SensorStateIndex,
) -> ServiceResult<Hmac> {
    //
    // Compute mac as HMAC_SHA256(key, msg) where
    // msg = nonce || user_id || sender_name || session_name
    //
    compute_hmac!(key, nonce, ssi, &sender, &session_type)
}

#[cfg(test)]
mod test {
    use super::{
        compute_hmac, decrypt_aes256_gcm, ec_keygen, ec_public_key_serialization,
        encrypt_aes256_gcm, perform_ecdh, Hmac, HmacGenerator, HmacSignable, Key, Secret,
    };
    use crate::error::ServiceResult;
    use std::array;

    // Struct used in tests to allow arbitrary blobs to be supplied to the HMAC generator.
    struct TestBlob(&'static [u8]);
    impl HmacSignable for TestBlob {
        fn update(
            &self,
            mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>,
        ) -> ServiceResult<()> {
            add_bytes(self.0)
        }
    }

    #[test]
    fn test_empty_hmac() {
        let key = Key { bytes: [0; 32] };
        let generator = HmacGenerator::new(&key).expect("could not construct HMAC generator");
        let hmac = generator.complete().expect("HMAC computation failed");
        let expected = [
            0xB6, 0x13, 0x67, 0x9A, 0x08, 0x14, 0xD9, 0xEC, 0x77, 0x2F, 0x95, 0xD7, 0x78, 0xC3,
            0x5F, 0xC5, 0xFF, 0x16, 0x97, 0xC4, 0x93, 0x71, 0x56, 0x53, 0xC6, 0xC7, 0x12, 0x14,
            0x42, 0x92, 0xC5, 0xAD,
        ];
        assert_eq!(hmac.bytes, expected);
    }

    #[test]
    fn test_basic_hmac() {
        let key = Key { bytes: array::from_fn(|i| (i + 1) as u8) };
        let mut generator = HmacGenerator::new(&key).expect("could not construct HMAC generator");
        generator.update(&TestBlob(b"Hello, World!")).expect("HMAC update failed");
        let hmac = generator.complete().expect("HMAC computation failed");
        let expected = [
            0x07, 0xF1, 0xBF, 0xCB, 0x5A, 0x28, 0xB0, 0xF4, 0x52, 0x75, 0xA7, 0x29, 0x07, 0xB0,
            0xE8, 0x45, 0x21, 0xF6, 0xEF, 0xE9, 0xD4, 0xFD, 0xE3, 0xDB, 0xE5, 0xED, 0x5E, 0xCE,
            0x1A, 0x99, 0x8B, 0x9E,
        ];
        assert_eq!(hmac.bytes, expected);
    }

    #[test]
    fn test_compute_hmac() {
        let key = Key { bytes: array::from_fn(|i| (i + 1) as u8) };
        let hmac =
            compute_hmac!(&key, &TestBlob(b"Hello, World!")).expect("HMAC computation failed");
        let expected = [
            0x07, 0xF1, 0xBF, 0xCB, 0x5A, 0x28, 0xB0, 0xF4, 0x52, 0x75, 0xA7, 0x29, 0x07, 0xB0,
            0xE8, 0x45, 0x21, 0xF6, 0xEF, 0xE9, 0xD4, 0xFD, 0xE3, 0xDB, 0xE5, 0xED, 0x5E, 0xCE,
            0x1A, 0x99, 0x8B, 0x9E,
        ];
        assert_eq!(hmac.bytes, expected);
    }

    #[test]
    fn test_multi_part_hmac() {
        let key = Key { bytes: array::from_fn(|i| (i + 1) as u8) };
        let mut generator = HmacGenerator::new(&key).expect("could not construct HMAC generator");
        generator.update(&TestBlob(b"Hello")).expect("HMAC update 1 failed");
        generator.update(&TestBlob(b", ")).expect("HMAC update 2 failed");
        generator.update(&TestBlob(b"World")).expect("HMAC update 3 failed");
        generator.update(&TestBlob(b"!")).expect("HMAC update 4 failed");
        let hmac = generator.complete().expect("HMAC computation failed");
        let expected = [
            0x07, 0xF1, 0xBF, 0xCB, 0x5A, 0x28, 0xB0, 0xF4, 0x52, 0x75, 0xA7, 0x29, 0x07, 0xB0,
            0xE8, 0x45, 0x21, 0xF6, 0xEF, 0xE9, 0xD4, 0xFD, 0xE3, 0xDB, 0xE5, 0xED, 0x5E, 0xCE,
            0x1A, 0x99, 0x8B, 0x9E,
        ];
        assert_eq!(hmac.bytes, expected);
    }

    #[test]
    fn test_multi_part_compute_hmac() {
        let key = Key { bytes: array::from_fn(|i| (i + 1) as u8) };
        let hmac = compute_hmac!(
            &key,
            &TestBlob(b"Hello"),
            &TestBlob(b", "),
            &TestBlob(b"World"),
            &TestBlob(b"!")
        )
        .expect("HMAC computation failed");
        let expected = [
            0x07, 0xF1, 0xBF, 0xCB, 0x5A, 0x28, 0xB0, 0xF4, 0x52, 0x75, 0xA7, 0x29, 0x07, 0xB0,
            0xE8, 0x45, 0x21, 0xF6, 0xEF, 0xE9, 0xD4, 0xFD, 0xE3, 0xDB, 0xE5, 0xED, 0x5E, 0xCE,
            0x1A, 0x99, 0x8B, 0x9E,
        ];
        assert_eq!(hmac.bytes, expected);
    }

    #[test]
    fn test_key_exchange() {
        // Generate two keys.
        let client_private = ec_keygen().expect("client keygen failed");
        let server_private = ec_keygen().expect("server keygen failed");
        // Do a Diffie-Hellman exchange.
        let client_public = ec_public_key_serialization(&client_private)
            .expect("could not get client public key bytes");
        let server_public = ec_public_key_serialization(&server_private)
            .expect("could not get server public key bytes");
        let client_key = perform_ecdh(client_private, server_public.as_slice())
            .expect("client handshake failed");
        let server_key = perform_ecdh(server_private, client_public.as_slice())
            .expect("server handshake failed");
        // We should now have matching keys.
        assert_eq!(client_key.bytes, server_key.bytes);
    }

    #[test]
    fn test_encrypt_round_trip() {
        let key = Key { bytes: array::from_fn(|i| i as u8 + 1) };
        let hmac = compute_hmac!(&key, &TestBlob(b"something")).expect("HMAC computation failed");
        let iv: [u8; 12] = array::from_fn(|i| i as u8);
        let plaintext = Secret { bytes: array::from_fn(|i| i as u8) };
        let mut tag = [0_u8; 16];
        let ciphertext = encrypt_aes256_gcm(&hmac, &iv, b"some_aad", &plaintext, &mut tag)
            .expect("encryption failed");
        assert_ne!(plaintext.bytes, ciphertext.as_slice());
        let decrypted = decrypt_aes256_gcm(&hmac, &iv, b"some_aad", &ciphertext, &tag)
            .expect("decryption failed");
        assert_eq!(plaintext.bytes, decrypted.bytes);
    }

    #[test]
    fn test_decrypt_fails() {
        let key = Key { bytes: array::from_fn(|i| i as u8 + 1) };
        let hmac = compute_hmac!(&key, &TestBlob(b"something")).expect("HMAC computation failed");
        let iv: [u8; 12] = array::from_fn(|i| i as u8);
        let plaintext = Secret { bytes: array::from_fn(|i| i as u8) };
        let mut tag = [0_u8; 16];
        let ciphertext = encrypt_aes256_gcm(&hmac, &iv, b"some_aad", &plaintext, &mut tag)
            .expect("encryption failed");
        decrypt_aes256_gcm(&Hmac { bytes: [0; 32] }, &iv, b"some_aad", &ciphertext, &tag)
            .err()
            .expect("decrypt worked with bad key");
        decrypt_aes256_gcm(&hmac, &[0; 12], b"some_aad", &ciphertext, &tag)
            .err()
            .expect("decrypt worked with bad IV");
        decrypt_aes256_gcm(&hmac, &iv, b"bad_aad", &ciphertext, &tag)
            .err()
            .expect("decrypt worked with bad AAD");
        decrypt_aes256_gcm(&hmac, &iv, b"some_aad", &ciphertext, &tag.map(|x| x + 1))
            .err()
            .expect("decrypt worked with bad tag");
    }
}
