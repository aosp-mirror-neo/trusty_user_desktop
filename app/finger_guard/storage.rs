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

//! Types and utilities for data which is stored persistently on the device.

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct SensorStateIndex {
    sensor_id: i32,
    user_id: i32,
}

impl SensorStateIndex {
    /// Construct an index for the given sensor and user.
    pub fn new(sensor_id: i32, user_id: i32) -> Self {
        SensorStateIndex { sensor_id, user_id }
    }

    /// The file name used to store persistent state associated with this index.
    pub fn authenticator_id_file_name(&self) -> String {
        format!("s{}.u{}.authenticator_id", self.sensor_id, self.user_id)
    }
}

#[derive(Hash, Eq, PartialEq, zerocopy::FromBytes)]
#[repr(C)]
/// Newtype that encapsulates an authenticator id.
pub struct AuthenticatorId(i64);

impl AuthenticatorId {
    /// Construct a default-value zero id.
    pub fn zero() -> Self {
        AuthenticatorId(0)
    }

    /// Convert the id to an i64.
    ///
    /// This should only be used to return the id across an AIDL interface. For
    /// storage the (de)serialization traits should be used.
    pub fn as_i64(&self) -> i64 {
        self.0
    }
}
