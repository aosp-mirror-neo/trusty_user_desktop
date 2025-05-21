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

use crate::error::ServiceError;
use fingerguard_api::aidl::SensorUserPair::SensorUserPair;
use storage::{OpenMode, Port, Session};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// A utility function to read the full content of a file.
fn read_all_bytes(file_name: &str) -> Result<Vec<u8>, storage::Error> {
    let mut session = Session::new(Port::TamperDetect, true)?;
    let secure_file = session.open_file(&file_name, OpenMode::Open)?;
    let file_size = session.get_size(&secure_file)?;
    let mut buffer = vec![0u8; file_size];
    let content = session.read_all(&secure_file, buffer.as_mut_slice())?;
    Ok(content.to_vec())
}

/// Indicates that the type is persisted as a file in the Trusty Storage.
///
/// This trait is required for types that keeps service states across reboots.
/// It provides a default save_to and load_from implementation, which should
/// satisfy the needs of most types.
///
/// # Safety
///
/// This trait does not guarantee thread safety against read write races.
pub trait PersistedState: FromBytes + IntoBytes + Immutable {
    fn load_from(file_name: &str) -> Result<Self, ServiceError>
    where
        Self: Sized,
    {
        let all_bytes = read_all_bytes(&file_name)
            .map_err(|e| ServiceError::TrustyFile("failed to read", file_name.to_owned(), e))?;
        Self::read_from_bytes(&all_bytes)
            .map_err(|_| ServiceError::ZcConvert("failed to deserialize file content"))
    }

    fn save_to(&self, file_name: &str) -> Result<(), ServiceError> {
        let mut session = Session::new(Port::TamperDetect, true)
            .map_err(|e| ServiceError::TrustyStorage("failed to create storage session", e))?;
        let mut secure_file = session
            .open_file(&file_name, OpenMode::Create)
            .map_err(|e| ServiceError::TrustyFile("open failed", file_name.to_owned(), e))?;
        let serialized_bytes = Self::as_bytes(&self);
        session
            .write_all(&mut secure_file, &serialized_bytes)
            .map_err(|e| ServiceError::TrustyFile("write failed", file_name.to_owned(), e))?;
        Ok(())
    }
}

/// Indicates that the type is pesisted to one single file.
///
/// This trait suits those global singleton service states.
/// This trait requires the type implement the PersistedState trait first.
///
/// # Safety
///
/// This trait does not guarantee thread safety against read write races.
pub trait SingleFileState: PersistedState {
    const FILE_NAME: &str;
    fn load() -> Result<Self, ServiceError>
    where
        Self: Sized,
    {
        Self::load_from(Self::FILE_NAME)
    }
    fn save(&self) -> Result<(), ServiceError>
    where
        Self: PersistedState,
    {
        Self::save_to(&self, Self::FILE_NAME)
    }
}

#[derive(Hash, Eq, PartialEq, Debug)]
/// Represents a key to index sensor state.
/// It is equivalent to a SensorUserPair defined in the service interface.
/// Within the service, this type should be used instead of the AIDL object.
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
    /// Big endian representation of user_id.
    pub fn user_id_be_bytes(&self) -> [u8; 4] {
        self.user_id.to_be_bytes()
    }
    /// The file name used to store persistent state associated with this index.
    pub fn authenticator_id_file_name(&self) -> String {
        format!("s{}.u{}.authenticator_id", self.sensor_id, self.user_id)
    }
}

#[derive(Default, Eq, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
/// Newtype that encapsulates an authenticator id.
pub struct AuthenticatorId(i64);

impl AuthenticatorId {
    /// Convert the id to an i64.
    ///
    /// This should only be used to return the id across an AIDL interface. For
    /// storage the (de)serialization traits should be used.
    pub fn as_i64(&self) -> i64 {
        self.0
    }
}

impl PersistedState for AuthenticatorId {}

#[derive(Default, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
/// Newtype that encapsulates the sensor session counter.
pub struct SensorSessionCounter(u64);
impl SensorSessionCounter {
    pub fn increment(&self) -> Self {
        Self(self.0 + 1)
    }
    /// Convert the id to an i64.
    ///
    /// This should only be used to return the counter across an AIDL interface. For
    /// storage the (de)serialization traits should be used.
    pub fn as_i64(&self) -> i64 {
        self.0 as i64
    }
}

impl PersistedState for SensorSessionCounter {}
impl SingleFileState for SensorSessionCounter {
    const FILE_NAME: &str = "fingerguard_sensor_session_counter";
}
