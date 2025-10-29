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

use crate::aidl::impl_export;
use crate::error::{ServiceError, ServiceResult};
use crate::hat::SignedHat;
use crate::identifiers::SensorStateIndex;
use crate::rng;
use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::{
    AuthenticationResult::AuthenticationResult, ClientSessionResponse::ClientSessionResponse,
    FinishEnrollSessionResponse::FinishEnrollSessionResponse, InitResponse::InitResponse,
    PrepareAuthSessionResponse::PrepareAuthSessionResponse,
    PrepareEnrollSessionResponse::PrepareEnrollSessionResponse,
    SdcpClientSessionResponse::SdcpClientSessionResponse,
};
use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::hmac::HmacCtx;
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sha::Sha256;
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
impl_export!(Nonce(self) => ClientSessionResponse.nonce as Vec<u8> {
    self.bytes.to_vec()
});
impl_export!(Nonce(self) => SdcpClientSessionResponse.nonce as Vec<u8> {
    self.bytes.to_vec()
});
impl_export!(Nonce(self) => PrepareAuthSessionResponse.nonce as [u8; 32] {
    self.bytes
});
impl HmacSignable for Nonce {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        add_bytes(&self.bytes)
    }
}

// Define a type for encryption IVs.
blob_newtype!(Iv, 12);
impl Iv {
    /// Securely generate a new IV.
    pub fn generate() -> Self {
        Self { bytes: rng::generate_random_buffer::<{ Self::SIZE }>() }
    }
}
impl_export!(Iv(self) => ClientSessionResponse.iv as Vec<u8> {
    self.bytes.to_vec()
});
impl_export!(Iv(self) => SdcpClientSessionResponse.iv as Vec<u8> {
    self.bytes.to_vec()
});

// Define a type for tags used in AES-256 encryption.
blob_newtype!(Aes256Tag, 16);
impl_export!(Aes256Tag(self) => ClientSessionResponse.tag as Vec<u8> {
    self.bytes.to_vec()
});
impl_export!(Aes256Tag(self) => SdcpClientSessionResponse.tag as Vec<u8> {
    self.bytes.to_vec()
});

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

// Define a type for the uncompressed representation of the public key point on the EC P256
// curve.
blob_newtype!(P256Point, 65);

impl P256Point {
    /// Import a P256 point that was supplied as a blob of bytes. Can fail if the size is incorrect.
    pub fn import(value: &[u8]) -> ServiceResult<Self> {
        Ok(Self {
            bytes: value.try_into().map_err(|_| ServiceError::BufferSizeMismatch {
                name: "EC p256 point",
                expected: P256Point::SIZE,
                actual: value.len(),
            })?,
        })
    }
    /// Convert to a created `EcKey<Public>`
    pub fn to_ec_key(&self) -> ServiceResult<EcKey<Public>> {
        let ec_key = (|| {
            let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
            let mut ctx = BigNumContext::new()?;
            let ec_point = EcPoint::from_bytes(&group, &self.bytes, &mut ctx)?;
            let public_key: EcKey<Public> = EcKey::from_public_key(&group, &ec_point)?;
            Ok(public_key)
        })()
        .wrap_openssl_err("failed to convert into a EcKey public key")?;
        Ok(ec_key)
    }
}

impl From<P256Point> for [u8; 65] {
    fn from(val: P256Point) -> [u8; 65] {
        val.bytes
    }
}

impl Hashable for P256Point {
    fn update(&self, mut add_bytes: impl FnMut(&[u8])) {
        add_bytes(&self.bytes)
    }
}

impl_export!(P256Point(self) => InitResponse.serverPublicKey as Vec<u8> {
    self.bytes.to_vec()
});
impl_export!(P256Point(self) => SdcpClientSessionResponse.serverPublicKey as Vec<u8> {
    self.bytes.to_vec()
});

// Define a type for the raw representation of a ECDSA P256 signature.
blob_newtype!(P256Sig, 64);

impl P256Sig {
    /// Import a raw P256 signature that was supplied as a blob of bytes. Can fail if the size is incorrect.
    pub fn import(value: &[u8]) -> ServiceResult<Self> {
        Ok(Self {
            bytes: value.try_into().map_err(|_| ServiceError::BufferSizeMismatch {
                name: "ECDSA p256 signature",
                expected: P256Sig::SIZE,
                actual: value.len(),
            })?,
        })
    }
    /// Convert to a created EcdsaSig.
    pub fn to_ecdsa_sig(&self) -> ServiceResult<EcdsaSig> {
        let sig = (|| {
            let r = BigNum::from_slice(&self.bytes[0..32])?;
            let s = BigNum::from_slice(&self.bytes[32..64])?;
            EcdsaSig::from_private_components(r, s)
        })()
        .wrap_openssl_err("failed to convert into a EcdsaSig")?;
        Ok(sig)
    }

    /// Verify self with the hash value in `dgst` using the EC public key in P256Point format.
    pub fn verify(&self, dgst: &HashValue, public_key: &P256Point) -> ServiceResult<bool> {
        let ecdsa_sig = &self.to_ecdsa_sig()?;
        let ec_key = public_key.to_ec_key()?;
        ecdsa_sig
            .verify(&dgst.bytes, &ec_key)
            .wrap_openssl_err("failed to verify a ECDSA signature")
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

/// Export a given EC private key's public key.
pub fn ec_public_key_serialization(
    private_key: &EcKey<Private>,
) -> Result<P256Point, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
    let mut ctx = BigNumContext::new()?;
    let public_key_bytes =
        private_key.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    let public_key = P256Point::import(&public_key_bytes)
        .expect("exported p256 uncomprsssed key should be 65 bytes");
    Ok(public_key)
}

/// Generate a 64-byte P256Sig with the hash value in `dgst` using the EC private key.
pub fn ecdsa_sign(dgst: &HashValue, ec_key: &EcKey<Private>) -> ServiceResult<P256Sig> {
    let sig = (|| {
        let ec_sig = EcdsaSig::sign(&dgst.bytes, ec_key)?;
        let r_bytes = ec_sig.r().to_vec_padded(32).expect("r must be at most 32 bytes");
        let s_bytes = ec_sig.s().to_vec_padded(32).expect("s must be at most 32 bytes");
        let sig_bytes = [&r_bytes[..], &s_bytes[..]].concat();
        Ok(P256Sig::import(&sig_bytes).expect("exact 64 bytes in sig_bytes."))
    })()
    .wrap_openssl_err("fail to create ecdsa signature")?;
    Ok(sig)
}

/// Perform a DH exchange using a private and public key, returning the new private key.
pub fn perform_ecdh(
    server_private_key: EcKey<Private>,
    client_public_key: &P256Point,
) -> ServiceResult<Key> {
    // Perform all of the crypto operations to produce the new key.
    let ec_key = client_public_key.to_ec_key()?;
    let pk = (|| {
        let server_private_key: PKey<Private> = server_private_key.try_into()?;
        let peer_public_key: PKey<Public> = ec_key.try_into()?;
        let mut pk_deriver = Deriver::new(&server_private_key)?;
        pk_deriver.set_peer(&peer_public_key)?;
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
    iv: &Iv,
    aad: &[u8],
    data: &Secret,
) -> Result<(Vec<u8>, Aes256Tag), openssl::error::ErrorStack> {
    let mut tag = Aes256Tag { bytes: [0u8; Aes256Tag::SIZE] };
    openssl::symm::encrypt_aead(
        Cipher::aes_256_gcm(),
        &key.bytes,
        Some(&iv.bytes),
        aad,
        &data.bytes,
        &mut tag.bytes,
    )
    .map(|enc_data| (enc_data, tag))
}

/// Decrypt a message using AES256-GCM with the given Hmac as a key.
pub fn decrypt_aes256_gcm(
    key: &Hmac,
    iv: &Iv,
    aad: &[u8],
    data: &[u8],
    tag: &Aes256Tag,
) -> ServiceResult<Secret> {
    let secret = openssl::symm::decrypt_aead(
        Cipher::aes_256_gcm(),
        &key.bytes,
        Some(&iv.bytes),
        aad,
        data,
        &tag.bytes,
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

// Define a type for the SHA-256 HMACs we use.
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
impl_export!(Hmac(self) => SignedHat.mac as Vec<u8> {
    self.bytes.to_vec()
});
impl_export!(Hmac(self) => InitResponse.pkMac as Vec<u8> {
    self.bytes.to_vec()
});
impl_export!(Hmac(self) => PrepareAuthSessionResponse.mac as Vec<u8> {
    self.bytes.to_vec()
});
impl From<Hmac> for PrepareEnrollSessionResponse {
    fn from(value: Hmac) -> Self {
        PrepareEnrollSessionResponse { mac: value.bytes.to_vec() }
    }
}
impl From<Hmac> for FinishEnrollSessionResponse {
    fn from(value: Hmac) -> Self {
        FinishEnrollSessionResponse { mac: value.bytes.to_vec() }
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

// Define a type for SHA256 message digest.
blob_newtype!(HashValue, 32);

impl HashValue {
    /// Import a SHA256 hash that was supplied as a blob of bytes. Can fail if the size is incorrect.
    pub fn import(value: &[u8]) -> ServiceResult<Self> {
        Ok(Self {
            bytes: value.try_into().map_err(|_| ServiceError::BufferSizeMismatch {
                name: "SHA256 hash value",
                expected: HashValue::SIZE,
                actual: value.len(),
            })?,
        })
    }
}

impl Hashable for HashValue {
    fn update(&self, mut add_bytes: impl FnMut(&[u8])) {
        add_bytes(&self.bytes)
    }
}

/// Generator which can consume bytes and produce a Sha256.
pub struct HashGenerator {
    context: Sha256,
}

/// Trait which types can implement to support being part of a hashed message.
pub trait Hashable {
    /// Update the hash with the relevant bytes from Self.
    fn update(&self, add_bytes: impl FnMut(&[u8]));
}

impl HashGenerator {
    /// Construct a new hash generator.
    pub fn new() -> Self {
        Self { context: Sha256::new() }
    }

    /// Update the hash with the given hashable object.
    pub fn update(&mut self, hashable: &impl Hashable) {
        hashable.update(|bytes| self.context.update(bytes))
    }

    /// Complete the generation of the HMAC, returning the final result.
    pub fn finish(self) -> HashValue {
        HashValue { bytes: self.context.finish() }
    }
}

impl Default for HashGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro which computes an Sha256 from a number of byte slices.
#[macro_export]
macro_rules! _compute_sha256 {
    ($($hashable:expr),*) => {
        {
            let mut generator = HashGenerator::new();
            $(generator.update($hashable);)*
            generator.finish()
        }
    };
}
pub use _compute_sha256 as compute_sha256;

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
        compute_hmac, compute_sha256, decrypt_aes256_gcm, ec_keygen, ec_public_key_serialization,
        encrypt_aes256_gcm, perform_ecdh, Aes256Tag, HashGenerator, Hmac, HmacGenerator,
        HmacSignable, Iv, Key, P256Point, P256Sig, Secret,
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
        let client_key =
            perform_ecdh(client_private, &server_public).expect("client handshake failed");
        let server_key =
            perform_ecdh(server_private, &client_public).expect("server handshake failed");
        // We should now have matching keys.
        assert_eq!(client_key.bytes, server_key.bytes);
    }

    #[test]
    fn test_encrypt_round_trip() {
        let key = Key { bytes: array::from_fn(|i| i as u8 + 1) };
        let hmac = compute_hmac!(&key, &TestBlob(b"something")).expect("HMAC computation failed");
        let iv = Iv { bytes: array::from_fn(|i| i as u8) };
        let plaintext = Secret { bytes: array::from_fn(|i| i as u8) };
        let (ciphertext, tag) =
            encrypt_aes256_gcm(&hmac, &iv, b"some_aad", &plaintext).expect("encryption failed");
        assert_ne!(plaintext.bytes, ciphertext.as_slice());
        let decrypted = decrypt_aes256_gcm(&hmac, &iv, b"some_aad", &ciphertext, &tag)
            .expect("decryption failed");
        assert_eq!(plaintext.bytes, decrypted.bytes);
    }

    #[test]
    fn test_decrypt_fails() {
        let key = Key { bytes: array::from_fn(|i| i as u8 + 1) };
        let hmac = compute_hmac!(&key, &TestBlob(b"something")).expect("HMAC computation failed");
        let iv = Iv { bytes: array::from_fn(|i| i as u8) };
        let plaintext = Secret { bytes: array::from_fn(|i| i as u8) };
        let (ciphertext, tag) =
            encrypt_aes256_gcm(&hmac, &iv, b"some_aad", &plaintext).expect("encryption failed");
        decrypt_aes256_gcm(&Hmac { bytes: [0; 32] }, &iv, b"some_aad", &ciphertext, &tag)
            .err()
            .expect("decrypt worked with bad key");
        decrypt_aes256_gcm(&hmac, &Iv { bytes: [0; 12] }, b"some_aad", &ciphertext, &tag)
            .err()
            .expect("decrypt worked with bad IV");
        decrypt_aes256_gcm(&hmac, &iv, b"bad_aad", &ciphertext, &tag)
            .err()
            .expect("decrypt worked with bad AAD");
        decrypt_aes256_gcm(&hmac, &iv, b"some_aad", &ciphertext, &Aes256Tag { bytes: [0; 16] })
            .err()
            .expect("decrypt worked with bad tag");
    }

    #[test]
    fn test_parse_p256_public_key() {
        let public_key_bytes: [u8; 65] = [
            0x04, 0xfd, 0xc8, 0xb2, 0xe0, 0xa2, 0x95, 0x12, 0x3f, 0x4a, 0x5b, 0x77, 0x13, 0xbc,
            0xc5, 0x2f, 0xf5, 0x50, 0x78, 0x19, 0x04, 0x4e, 0xa1, 0x48, 0x17, 0xb6, 0xa5, 0xb9,
            0x94, 0xd7, 0xe7, 0x85, 0xff, 0x8c, 0xdd, 0x49, 0x09, 0x91, 0xda, 0xf4, 0x81, 0x5a,
            0xa1, 0x89, 0xfc, 0xa6, 0xee, 0x26, 0x45, 0xdd, 0x6c, 0xf6, 0x6e, 0xb1, 0x61, 0x35,
            0xdf, 0xa0, 0xec, 0xb5, 0x77, 0x44, 0xf7, 0xd2, 0x95,
        ];
        let p256_point = P256Point::import(&public_key_bytes).unwrap();
        let _ = p256_point.to_ec_key();
    }

    #[test]
    fn test_parse_p256sig() {
        let sig: [u8; 64] = [
            0x34, 0x51, 0x71, 0x9a, 0xab, 0x29, 0x1a, 0x3f, 0x37, 0x14, 0x03, 0xb2, 0xc3, 0x19,
            0xcc, 0x40, 0xba, 0x18, 0x4e, 0xee, 0xcf, 0x8d, 0xbc, 0x9d, 0x23, 0x40, 0x20, 0xbe,
            0x15, 0x24, 0xfd, 0xbd, 0xc1, 0xfb, 0xed, 0x69, 0x6d, 0xf5, 0xe9, 0xb5, 0xc6, 0x34,
            0x6b, 0xa0, 0x27, 0x3c, 0x75, 0x65, 0xd9, 0xe1, 0x3d, 0x8a, 0xa4, 0xf7, 0xa0, 0x45,
            0x57, 0x76, 0x47, 0x10, 0x67, 0xe0, 0xff, 0xa6,
        ];
        let p256_sig = P256Sig::import(&sig).unwrap();
        let _ = p256_sig.to_ecdsa_sig().unwrap();
    }

    #[test]
    fn test_verify_p256sig() {
        // a dev firmware model key
        let model_key_bytes: [u8; 65] = [
            0x04, 0xdb, 0x68, 0x13, 0x51, 0xcf, 0xec, 0x9a, 0x92, 0xce, 0x00, 0xba, 0x17, 0xc6,
            0xbe, 0xd2, 0xd8, 0x5b, 0x1d, 0xb8, 0xd6, 0xbf, 0x07, 0x82, 0xad, 0xe7, 0xc6, 0xbe,
            0x69, 0xe2, 0x1d, 0x1a, 0x45, 0x7b, 0x40, 0x8c, 0xac, 0xc7, 0x4d, 0x89, 0x79, 0x98,
            0x68, 0x74, 0x10, 0xcd, 0x45, 0xe4, 0xfb, 0xff, 0x62, 0x73, 0x0e, 0xbc, 0xc8, 0x7d,
            0xac, 0x81, 0xf6, 0xb2, 0xba, 0x12, 0x6c, 0x1e, 0x8a,
        ];
        // the dev key signing key.
        let ksk_public_key_bytes: [u8; 65] = [
            0x04, 0xfd, 0xc8, 0xb2, 0xe0, 0xa2, 0x95, 0x12, 0x3f, 0x4a, 0x5b, 0x77, 0x13, 0xbc,
            0xc5, 0x2f, 0xf5, 0x50, 0x78, 0x19, 0x04, 0x4e, 0xa1, 0x48, 0x17, 0xb6, 0xa5, 0xb9,
            0x94, 0xd7, 0xe7, 0x85, 0xff, 0x8c, 0xdd, 0x49, 0x09, 0x91, 0xda, 0xf4, 0x81, 0x5a,
            0xa1, 0x89, 0xfc, 0xa6, 0xee, 0x26, 0x45, 0xdd, 0x6c, 0xf6, 0x6e, 0xb1, 0x61, 0x35,
            0xdf, 0xa0, 0xec, 0xb5, 0x77, 0x44, 0xf7, 0xd2, 0x95,
        ];
        // signature produced by the dev key signing process.
        let sig: [u8; 64] = [
            0x34, 0x51, 0x71, 0x9a, 0xab, 0x29, 0x1a, 0x3f, 0x37, 0x14, 0x03, 0xb2, 0xc3, 0x19,
            0xcc, 0x40, 0xba, 0x18, 0x4e, 0xee, 0xcf, 0x8d, 0xbc, 0x9d, 0x23, 0x40, 0x20, 0xbe,
            0x15, 0x24, 0xfd, 0xbd, 0xc1, 0xfb, 0xed, 0x69, 0x6d, 0xf5, 0xe9, 0xb5, 0xc6, 0x34,
            0x6b, 0xa0, 0x27, 0x3c, 0x75, 0x65, 0xd9, 0xe1, 0x3d, 0x8a, 0xa4, 0xf7, 0xa0, 0x45,
            0x57, 0x76, 0x47, 0x10, 0x67, 0xe0, 0xff, 0xa6,
        ];
        let p256_sig = P256Sig::import(&sig).unwrap();
        let ksk_key = P256Point::import(&ksk_public_key_bytes).unwrap();
        let model_key = P256Point::import(&model_key_bytes).unwrap();
        let dgst = compute_sha256!(&model_key);
        assert!(p256_sig.verify(&dgst, &ksk_key).unwrap());
    }
}
