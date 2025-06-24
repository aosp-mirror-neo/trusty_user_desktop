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

//! Common functions and data structures dealing with HardwareAuthToken

use crate::clock::Instant;
use crate::crypto::{self, HmacGenerator, HmacSignable};
use crate::error::ServiceResult;
use crate::storage::{AuthenticatorId, SecureUserId};
use fingerguard_api::aidl::HardwareAuthToken::HardwareAuthToken;

/// Represents an unsigned hardware auth token.
pub struct UnsignedHat {
    version: i8,
    challenge: i64,
    user_id: SecureUserId,
    authenticator_id: AuthenticatorId,
    authenticator_type: AuthenticatorType,
    timestamp: Instant,
}

/// Represents a signed hardware auth token.
pub type SignedHat = fingerguard_api::aidl::HardwareAuthToken::HardwareAuthToken;

impl UnsignedHat {
    /// Construct a new hardware auth token with the given parameters and timestamp.
    pub fn new(
        challenge: i64,
        user_id: SecureUserId,
        authenticator_id: AuthenticatorId,
        authenticator_type: AuthenticatorType,
        timestamp: Instant,
    ) -> Self {
        Self { version: 0, challenge, user_id, authenticator_id, authenticator_type, timestamp }
    }

    /// Attempt to convert the unsigned token into a signed one, using the given key.
    pub fn sign(&self, key: &crypto::Key) -> ServiceResult<HardwareAuthToken> {
        let mut hat = HardwareAuthToken::default();
        hat.version = self.version;
        hat.challenge = self.challenge;
        self.user_id.export(&mut hat);
        self.authenticator_id.export(&mut hat);
        self.authenticator_type.export(&mut hat);
        self.timestamp.export(&mut hat);
        hat.mac = HmacGenerator::compute_with(key, &hat)?.into();
        Ok(hat)
    }
}

/// Trait that is implemented by the constituent parts of a token for export+signing.
pub trait ExportToHat {
    fn export(&self, out: &mut SignedHat);
}

pub const EMPTY_HAT: HardwareAuthToken = HardwareAuthToken {
    version: 0,
    challenge: 0,
    userId: 0,
    authenticatorId: 0,
    authenticatorType: 0,
    timestamp: 0,
    mac: vec![],
};

/// Newtype for authenticator type as a bit mask in HardwareAuthToken.
/// Four types are defined in hw_auth_token.h:
/// 0 for None, and 0xFFFFFFFF for Any. Individual type must be
/// powers of 2: 1 for password; 2 for fingerprint.
/// In practice, we never see more than 1 type to be set.
pub struct AuthenticatorType(u32);

impl AuthenticatorType {
    pub const FINGERPRINT: Self = Self(2);
}

impl ExportToHat for AuthenticatorType {
    fn export(&self, out: &mut HardwareAuthToken) {
        out.authenticatorType = self.0 as i32;
    }
}

/// Helper to compute the MAC for a given HardwareAuthToken.
///
/// The MAC is a 32 bytes HMAC-SHA256 with the auth token signing key over the
/// following string
///         version || challenge || user_id || authenticator_id || authenticator_type || timestamp
///
/// where ``||'' represents concatenation, the leading version is a single
/// byte, and all integers are represented as unsigned values, the full width
/// of the type.  The challenge, userId and authenticatorId values are in
/// machine order, but authenticatorType and timestamp are in network order
/// (big-endian). This odd construction is compatible with the hw_auth_token_t
/// structure.
impl HmacSignable for HardwareAuthToken {
    fn update(&self, generator: &mut HmacGenerator) -> ServiceResult<()> {
        generator.update(&self.version.to_ne_bytes())?;
        generator.update(&self.challenge.to_ne_bytes())?;
        generator.update(&self.userId.to_ne_bytes())?;
        generator.update(&self.authenticatorId.to_ne_bytes())?;
        generator.update(&self.authenticatorType.to_be_bytes())?;
        generator.update(&self.timestamp.to_be_bytes())
    }
}
