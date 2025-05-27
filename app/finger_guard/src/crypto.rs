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

use crate::error::{ServiceError, ServiceResult};
use crate::storage::{SensorSessionCounter, SensorStateIndex};
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hmac::HmacCtx;
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};

/// Standard size for most chunks of entropy.
pub const ENTROPY_SIZE: usize = 32;
/// Standard fixed-size block of entropy, generally a key.
pub type FixedSizeEntropy = [u8; ENTROPY_SIZE];

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
        private_key.public_key().to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?;
    Ok(server_public_key_bytes)
}

/// Perform a DH exchange using a private and public key, returning the new private key.
pub fn perform_ecdh(
    server_private_key: &PKey<Private>,
    client_public_key_bytes: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
    let mut ctx = BigNumContext::new()?;
    let client_public_point = EcPoint::from_bytes(&group, &client_public_key_bytes, &mut ctx)?;
    let client_public_key: PKey<Public> =
        EcKey::from_public_key(&group, &client_public_point)?.try_into()?;
    let mut pk_deriver = Deriver::new(&server_private_key)?;
    pk_deriver.set_peer(&client_public_key)?;
    let pk = pk_deriver.derive_to_vec()?;
    Ok(pk)
}

pub enum MessageSender {
    FINGERGUARD,
    FPMCU,
}

pub enum SensorSessionType {
    ENROLL,
    AUTH,
}

/// Generator which can consume bytes and produce an HMAC.
///
/// The HMACs used by finger guard are based on SHA-256 hashes.
pub struct HmacGenerator {
    context: HmacCtx,
}

impl HmacGenerator {
    /// Construct a new HMAC generator that will use the given key.
    pub fn new(key: &FixedSizeEntropy) -> ServiceResult<Self> {
        Ok(Self {
            context: HmacCtx::new(key, Md::sha256())
                .map_err(|e| ServiceError::OpenSsl("unable to initialize hmac", e))?,
        })
    }

    /// Update the HMAC with the given chunk of bytes.
    pub fn update(&mut self, buffer: &[u8]) -> ServiceResult<()> {
        self.context.update(buffer).map_err(|e| ServiceError::OpenSsl("unable to update hmac", e))
    }

    /// Complete the generation of the HMAC, returning the final result.
    pub fn complete(mut self) -> ServiceResult<FixedSizeEntropy> {
        let mut hmac = FixedSizeEntropy::default();
        self.context
            .finalize(hmac.as_mut_slice())
            .map_err(|e| ServiceError::OpenSsl("unable to finalize hmac", e))?;
        Ok(hmac)
    }

    /// Compute an HMAC using the given key and buffer.
    ///
    /// This is a useful helper method that simplifies the very common case of
    /// computing an HMAC using a single pre-existing buffer of bytes.
    pub fn compute(key: &FixedSizeEntropy, buffer: &[u8]) -> ServiceResult<FixedSizeEntropy> {
        let mut generator = Self::new(key)?;
        generator.update(buffer)?;
        Ok(generator.complete()?)
    }
}

/// Helper to compute the HMAC for the enrollment/authentication
/// session messages from this service or from the sensor.
pub fn sensor_session_message_hmac(
    key: &FixedSizeEntropy,
    nonce: &FixedSizeEntropy,
    sender: MessageSender,
    session_type: SensorSessionType,
    ssi: &SensorStateIndex,
    session_counter: &SensorSessionCounter,
) -> ServiceResult<FixedSizeEntropy> {
    let sender_name: &[u8] = match sender {
        MessageSender::FINGERGUARD => b"fingerguard",
        MessageSender::FPMCU => b"fpmcu",
    };
    let session_name: &[u8] = match session_type {
        SensorSessionType::ENROLL => b"enroll",
        SensorSessionType::AUTH => b"auth",
    };
    //
    // Compute mac as HMAC_SHA256(key, msg) where
    // msg = nonce || user_id || sender_name || session_name || session_counter
    //
    let mut generator = HmacGenerator::new(key)?;
    generator.update(nonce.as_slice())?;
    generator.update(&ssi.user_id_be_bytes())?;
    generator.update(sender_name)?;
    generator.update(session_name)?;
    generator.update(&session_counter.as_i64().to_be_bytes())?;
    Ok(generator.complete()?)
}
