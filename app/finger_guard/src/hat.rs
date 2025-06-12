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

use crate::crypto;
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
    hat.mac = crypto::hardware_auth_token_mac(key, &hat)?.into();
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
