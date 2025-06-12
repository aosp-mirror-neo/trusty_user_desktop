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

use crate::crypto::{self, HmacGenerator, HmacSignable};
use crate::error::ServiceResult;
use fingerguard_api::aidl::HardwareAuthToken::HardwareAuthToken;

pub trait HatChallenge {
    fn value(&self) -> i64;
}

pub trait HatUserId {
    fn value(&self) -> i64;
}

pub trait HatAuthenticatorId {
    fn value(&self) -> i64;
}

pub trait HatAuthenticatorType {
    fn value(&self) -> i32;
}

pub trait HatTimestamp {
    fn value(&self) -> i64;
}

impl HatChallenge for i64 {
    fn value(&self) -> i64 {
        *self
    }
}

pub fn make_signed_hat(
    key: &crypto::Key,
    challenge: &impl HatChallenge,
    user_id: &impl HatUserId,
    authenticator_id: &impl HatAuthenticatorId,
    authenticator_type: &impl HatAuthenticatorType,
    timestamp: &impl HatTimestamp,
) -> ServiceResult<HardwareAuthToken> {
    let mut hat = HardwareAuthToken {
        version: 0,
        challenge: challenge.value(),
        userId: user_id.value(),
        authenticatorId: authenticator_id.value(),
        authenticatorType: authenticator_type.value(),
        timestamp: timestamp.value(),
        mac: vec![],
    };
    hat.mac = HmacGenerator::compute_with(key, &hat)?.into();
    Ok(hat)
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

impl HatAuthenticatorType for AuthenticatorType {
    fn value(&self) -> i32 {
        self.0 as i32
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
