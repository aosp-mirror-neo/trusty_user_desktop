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

use crate::aidl::{export_field, impl_export, ExportAidlField};
use crate::crypto::{self, HmacSignable};
use crate::error::ServiceResult;
use crate::identifiers::{AuthenticatorId, SecureUserId};
use crate::time::Instant;
use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::HardwareAuthToken::HardwareAuthToken;

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
pub type SignedHat = HardwareAuthToken;

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
    pub fn sign(&self, key: &crypto::Key) -> ServiceResult<SignedHat> {
        let mut hat = SignedHat {
            version: self.version,
            challenge: self.challenge,
            userId: self.user_id.export(),
            authenticatorId: self.authenticator_id.export(),
            authenticatorType: self.authenticator_type.export(),
            timestamp: self.timestamp.export(),
            mac: Default::default(),
        };
        hat.mac = export_field!(&crypto::compute_hmac!(key, &hat)? => SignedHat.mac);
        Ok(hat)
    }
}

/// The standard default empty hardware token.
pub const EMPTY_HAT: SignedHat = SignedHat {
    version: 0,
    challenge: 0,
    userId: 0,
    authenticatorId: 0,
    authenticatorType: 0,
    timestamp: 0,
    mac: [0; 32],
};

/// Newtype for authenticator type as a bit mask in HardwareAuthToken.
/// Four types are defined in hw_auth_token.h:
/// 0 for None, and 0xFFFFFFFF for Any. Individual type must be
/// powers of 2: 1 for password; 2 for fingerprint.
/// In practice, we never see more than 1 type to be set.
#[derive(PartialEq, Debug)]
pub struct AuthenticatorType(u32);

impl AuthenticatorType {
    /// None authenticator.
    pub const NONE: Self = Self(0);
    /// A password authenticator.
    pub const PASSWORD: Self = Self(1);
    /// A fingerprint authenticator.
    pub const FINGERPRINT: Self = Self(2);
}

impl_export!(AuthenticatorType(self) => SignedHat.authenticatorType as i32 {
    self.0 as i32
});

// This is implemented as the inverse of ExportToAidl. It is not a typical usage of From trait: it
// is not lossless and it operates on the borrowed object.
impl From<&SignedHat> for AuthenticatorType {
    fn from(hat: &SignedHat) -> Self {
        Self(hat.authenticatorType as u32)
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
impl HmacSignable for SignedHat {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        add_bytes(&self.version.to_ne_bytes())?;
        add_bytes(&self.challenge.to_ne_bytes())?;
        add_bytes(&self.userId.to_ne_bytes())?;
        add_bytes(&self.authenticatorId.to_ne_bytes())?;
        add_bytes(&self.authenticatorType.to_be_bytes())?;
        add_bytes(&self.timestamp.to_be_bytes())
    }
}
