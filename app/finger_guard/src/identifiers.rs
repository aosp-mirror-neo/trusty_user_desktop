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

//! Identifier types that are significant to finger_guard.
//!
//! These types are meant for use in external APIs and/or persistent storage and so they have
//! meaning beyond the internal process state and so should be modified only very carefully.

use crate::aidl::impl_export;
use crate::crypto::HmacSignable;
use crate::error::ServiceResult;
use crate::hat::SignedHat;
use crate::rng;
use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::SensorUserPair::SensorUserPair;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Represents a key to index sensor state.
///
/// It is equivalent to a SensorUserPair defined in the service interface.
/// Within the service, this type should be used instead of the AIDL object.
#[derive(Copy, Clone, PartialOrd, Ord, Eq, PartialEq, Debug)]
pub struct SensorStateIndex {
    sensor_id: u32,
    user_id: u32,
}

impl From<&SensorUserPair> for SensorStateIndex {
    fn from(sensor_user_pair: &SensorUserPair) -> Self {
        SensorStateIndex {
            sensor_id: sensor_user_pair.sensorId as u32,
            user_id: sensor_user_pair.userId as u32,
        }
    }
}

impl SensorStateIndex {
    /// The file name for the authenticator id with this index.
    pub fn authenticator_id_file_name(&self) -> String {
        format!("s{}.u{}.authenticator_id", self.sensor_id, self.user_id)
    }
    /// The file name for the secure user id with this index.
    pub fn secure_user_id_file_name(&self) -> String {
        format!("s{}.u{}.secure_user_id", self.sensor_id, self.user_id)
    }
}

impl HmacSignable for SensorStateIndex {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        // Only the user id is incorporated into messages.
        // Little-endian encoding is preferred by FPMCU.
        add_bytes(&self.user_id.to_le_bytes())
    }
}

/// Newtype that encapsulates an authenticator id.
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct AuthenticatorId(i64);

impl AuthenticatorId {
    /// Generate a new random authenticator id.
    pub fn generate_random() -> Self {
        Self(rng::generate_random_int!(i64))
    }
}

impl From<AuthenticatorId> for i64 {
    fn from(value: AuthenticatorId) -> Self {
        value.0
    }
}
impl_export!(AuthenticatorId(self) => SignedHat.authenticatorId as i64 {
    self.0
});

/// Newtype that encapsulates a secure user id.
#[derive(Copy, Clone, Default, Eq, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct SecureUserId(u64);

impl From<i64> for SecureUserId {
    fn from(value: i64) -> Self {
        Self(value as u64)
    }
}
impl_export!(SecureUserId(self) => SignedHat.userId as i64 {
    self.0 as i64
});

#[cfg(test)]
mod test {
    use super::SensorStateIndex;
    use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::SensorUserPair::SensorUserPair;

    #[test]
    fn test_index_from_pair() {
        let pair = SensorUserPair { sensorId: 314159, userId: 271828 };
        let index = SensorStateIndex::from(&pair);
        assert_eq!(index, SensorStateIndex { sensor_id: 314159, user_id: 271828 });
    }

    #[test]
    fn test_auth_id_file_name() {
        let index = SensorStateIndex::from(&SensorUserPair { sensorId: 314159, userId: 271828 });
        assert_eq!(index.authenticator_id_file_name(), "s314159.u271828.authenticator_id");
    }

    #[test]
    fn test_user_id_file_name() {
        let index = SensorStateIndex::from(&SensorUserPair { sensorId: 314159, userId: 271828 });
        assert_eq!(index.secure_user_id_file_name(), "s314159.u271828.secure_user_id");
    }
}
