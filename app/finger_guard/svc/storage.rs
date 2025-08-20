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

//! Utilities and traits for reading and writing types from Trusty Storage.

use finger_guard::error::{ServiceError, ServiceResult};
use storage::{OpenMode, Port, Session};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Extend Result with functions that can map trusty storage errors to service errors.
trait MapStorageErrExt<T> {
    fn wrap_storage_err(self, msg: &'static str) -> ServiceResult<T>;
    fn wrap_file_err(self, msg: &'static str, file_name: String) -> ServiceResult<T>;
}
impl<T> MapStorageErrExt<T> for Result<T, storage::Error> {
    fn wrap_storage_err(self, msg: &'static str) -> ServiceResult<T> {
        self.map_err(|e| ServiceError::TrustyStorage(msg, Box::new(e)))
    }
    fn wrap_file_err(self, msg: &'static str, file_name: String) -> ServiceResult<T> {
        self.map_err(|e| ServiceError::TrustyFile(msg, file_name, Box::new(e)))
    }
}

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
    fn load_from(file_name: &str) -> ServiceResult<Self>
    where
        Self: Sized,
    {
        let all_bytes =
            read_all_bytes(&file_name).wrap_file_err("failed to read", file_name.to_owned())?;
        Self::read_from_bytes(&all_bytes)
            .map_err(|_| ServiceError::ZcConvert("failed to deserialize file content"))
    }

    fn save_to(&self, file_name: &str) -> ServiceResult<()> {
        let mut session = Session::new(Port::TamperDetect, true)
            .wrap_storage_err("failed to create storage session")?;
        let mut secure_file = session
            .open_file(&file_name, OpenMode::Create)
            .wrap_file_err("open failed", file_name.to_owned())?;
        let serialized_bytes = Self::as_bytes(&self);
        session
            .write_all(&mut secure_file, &serialized_bytes)
            .wrap_file_err("write failed", file_name.to_owned())?;
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
    fn load() -> ServiceResult<Self>
    where
        Self: Sized,
    {
        Self::load_from(Self::FILE_NAME)
    }
    fn save(&self) -> ServiceResult<()>
    where
        Self: PersistedState,
    {
        Self::save_to(&self, Self::FILE_NAME)
    }
}
