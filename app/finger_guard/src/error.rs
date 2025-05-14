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

//! Error types for the finger guard service.

/// Common error type for errors within the service implementation.
///
/// The actual service layer returns binder::Result errors but that type is
/// basically just a status code that lacks the ability to attach any kind of
/// informative message or underlying source error.
#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
    // Wrapping errors or pseudo-errors that are returned by other libraries.
    #[error("{0}: openssl error: {1:?}")]
    OpenSsl(&'static str, #[source] openssl::error::ErrorStack),
    #[error("{0}: trusty storage error: {1:?}")]
    TrustyStorage(&'static str, storage::Error),
    #[error("{0}: trusty storage file error at {1}: {2:?}")]
    TrustyFile(&'static str, String, storage::Error),
    #[error("{0}: zerocopy conversion error")]
    ZcConvert(&'static str),
    #[error("{0}: {1:?}")]
    TipcError(&'static str, tipc::TipcError),

    // Errors from interacting with keymint.
    #[error("Keymint {cmd} returned an error code: {code}")]
    KeymintError { cmd: &'static str, code: u32 },
    #[error("Keymint {cmd} returned an unparseable response")]
    KeymintBadResponse { cmd: &'static str },

    // Errors directly reported by the service implementation itself.
    #[error("{name} buffer size mismatch, expected {expected}, got {actual}")]
    BufferSizeMismatch { name: &'static str, expected: usize, actual: usize },
    #[error("failed to acquire {name} {mode} lock")]
    LockAcquire { name: &'static str, mode: &'static str },
    #[error("invalid argument {0}")]
    InvalidArg(&'static str),
    #[error("internal state {0} already exists")]
    StateAlreadyExists(&'static str),
    #[error("internal state {0} was unavailable")]
    StateUnavailable(&'static str),
}

/// Common Result type for service methods.
///
/// This is the standard Result type to use for internal service functions.
pub type ServiceResult<T> = Result<T, ServiceError>;
