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
    /// Wrap an error from openssl.
    #[error("{0}: openssl error: {1:?}")]
    OpenSsl(&'static str, #[source] Box<dyn std::error::Error>),
    /// Wrap an error from the trusty storage system.
    #[error("{0}: trusty storage error: {1:?}")]
    TrustyStorage(&'static str, Box<dyn std::fmt::Debug>),
    /// Wrap a file-specific error from the trusty storage system.
    #[error("{0}: trusty storage file error at {1}: {2:?}")]
    TrustyFile(&'static str, String, Box<dyn std::fmt::Debug>),
    /// Wrap a zerocopy conversion error.
    #[error("{0}: zerocopy conversion error")]
    ZcConvert(&'static str),
    /// Wrap a TIPC communication error.
    #[error("{0}: {1:?}")]
    TipcError(&'static str, Box<dyn std::fmt::Debug>),
    /// Wrap a trusty system error, including the underlying error code.
    #[error("Trusty system api {0} returns an error code: {1}")]
    TrustySysRcError(&'static str, i64),

    /// Keymint failed with an error code.
    #[error("Keymint {cmd} returned an error code: {code}")]
    KeymintError {
        /// Failed Keymint command.
        cmd: &'static str,
        /// Error code returned by Keymint.
        code: u32,
    },
    /// Keymint returned a response that could not be parsed.
    #[error("Keymint {cmd} returned an unparseable response")]
    KeymintBadResponse {
        /// Failed Keymint command.
        cmd: &'static str,
    },

    /// An authentication error that occurred due to auth lockout.
    #[error("Auth lockout error: {0:?}")]
    AuthLockoutError(Box<dyn std::error::Error>),
    /// An error occurred where a given buffer/blob was the wrong size.
    #[error("{name} buffer size mismatch, expected {expected}, got {actual}")]
    BufferSizeMismatch {
        /// Name of the buffer.
        name: &'static str,
        /// Expected size of the buffer.
        expected: usize,
        /// Actual size of the buffer.
        actual: usize,
    },
    /// An error occurred while acquiring a necessary lock. This should not actually happen in
    /// practice because finger_guard is single threaded.
    #[error("failed to acquire {0} lock")]
    LockAcquire(&'static str),
    /// Returned when an invalid argument is provided to the service. This should not normally
    /// be used for internal functions.
    #[error("invalid argument {0}")]
    InvalidArg(&'static str),
    /// Returned when attempting to initialize internal state which has already been initialized.
    #[error("internal state {0} already exists")]
    StateAlreadyExists(&'static str),
    /// Returned when internal state is expected to exist but does not.
    #[error("internal state {0} was unavailable")]
    StateUnavailable(&'static str),
    /// Returned when an HMAC check on a request fails. Similar to InvalidArg but not quite the
    /// same: passing in a blob which is not a valid HMAC would be InvalidArg, but passing in
    /// a blob with a valid-but-incorrect HMAC would be BadMac.
    #[error("incorrect mac for {0}")]
    BadMac(&'static str),
}

/// Common Result type for service methods.
///
/// This is the standard Result type to use for internal service functions.
pub type ServiceResult<T> = Result<T, ServiceError>;

#[cfg(test)]
mod test {
    use super::ServiceError;

    #[test]
    fn test_simple_error() {
        let err = ServiceError::BadMac("abc");
        assert_eq!(err.to_string(), "incorrect mac for abc");
    }
}
