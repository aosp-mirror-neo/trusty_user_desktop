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

//! Fake implementations of some traits for use in testing.
use crate::crypto::Key;
use crate::error::{ServiceError, ServiceResult};
use crate::identifiers::{AuthenticatorId, SecureUserId};
use crate::service::{InitParams, TrustyEnvironment};
use crate::time::{Clock, Instant};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;
use zerocopy::{FromBytes, Immutable, IntoBytes};

// The simulated clock and trusty structures in here protect all of their internal simulated state
// with mutexes. This is for two reasons:
//   * these traits are expected to be thread-safe
//   * we need to be able to manipulate internal state to control the simulation
// The mutex provides both the safety and interior mutability.

/// A simulated clock implementation for testing. It provides additional functions to allow the
/// test code to control the current time that it will report.
pub struct SimulatedClock {
    current_time: Mutex<Instant>,
}
impl SimulatedClock {
    /// Creates a new simulated clock.
    ///
    /// Note that this will allocate a new clock globally which cannot be deallocated, so individual
    /// tests should not create more than one instance of this. Since the clock is conceptually
    /// intended to be a singleton this should not be a serious limitation in practice.
    pub fn new() -> &'static Self {
        Box::leak(Box::new(Self { current_time: Mutex::new(Instant::MIN) }))
    }

    /// Advances the clock by a specified duration.
    pub fn advance_time(&self, duration: Duration) {
        let mut now = self.current_time.lock().unwrap();
        *now = *now + duration;
    }
}

impl Clock for SimulatedClock {
    fn now(&self) -> ServiceResult<Instant> {
        Ok(*self.current_time.lock().unwrap())
    }
}

/// A fake trusty environment.
///
/// Instead of a real clock and real files this environment uses a simulated clock and stores the
/// key and file contents in memory.
pub struct SimulatedTrusty {
    clock: &'static SimulatedClock,
    auth_token_key: Mutex<Vec<u8>>,
    files: Mutex<BTreeMap<String, Vec<u8>>>,
}
impl SimulatedTrusty {
    /// Create a new simulated trusty environment.
    ///
    /// The default environement includes a clock and no stored internal contents. Tests that want
    /// to set up some additional initial state can do so using helpers provided.
    pub fn new() -> Self {
        Self {
            clock: SimulatedClock::new(),
            auth_token_key: Default::default(),
            files: Default::default(),
        }
    }

    pub fn simulated_clock(&self) -> &'static SimulatedClock {
        self.clock
    }

    /// Set the auth token key.
    pub fn set_auth_token_key(&self, key: &Key) {
        let mut stored_key = self.auth_token_key.lock().unwrap();
        *stored_key = key.as_bytes().to_vec();
    }

    fn load_bytes<T: FromBytes>(&self, filename: &str) -> ServiceResult<T> {
        let files = self.files.lock().unwrap();
        match files.get(filename) {
            Some(bytes) => Ok(T::read_from_bytes(bytes).unwrap()),
            _ => Err(ServiceError::TrustyFile(
                "not found",
                filename.to_owned(),
                Box::new("not found"),
            )),
        }
    }
    fn save_bytes<T: IntoBytes + Immutable>(
        &self,
        object: &T,
        filename: &str,
    ) -> ServiceResult<()> {
        let mut files = self.files.lock().unwrap();
        files.insert(filename.to_owned(), object.as_bytes().to_vec());
        Ok(())
    }
}
impl TrustyEnvironment for SimulatedTrusty {
    fn clock(&self) -> &dyn Clock {
        self.clock
    }
    fn get_auth_token_key(&self) -> ServiceResult<Key> {
        let key = self.auth_token_key.lock().unwrap();
        Key::read_from_bytes(key.as_slice())
            .map_err(|_| ServiceError::StateUnavailable("no auth token key"))
    }
    fn load_init_params(&self) -> ServiceResult<InitParams> {
        self.load_bytes::<InitParams>(InitParams::FILE_NAME)
    }
    fn save_init_params(&self, init_params: &InitParams) -> ServiceResult<()> {
        self.save_bytes(init_params, InitParams::FILE_NAME)
    }
    fn load_authenticator_id(&self, filename: &str) -> ServiceResult<AuthenticatorId> {
        self.load_bytes::<AuthenticatorId>(filename)
    }
    fn save_authenticator_id(
        &self,
        auth_id: &AuthenticatorId,
        filename: &str,
    ) -> ServiceResult<()> {
        self.save_bytes(auth_id, filename)
    }
    fn load_user_id(&self, filename: &str) -> ServiceResult<SecureUserId> {
        self.load_bytes::<SecureUserId>(filename)
    }
    fn save_user_id(&self, user_id: &SecureUserId, filename: &str) -> ServiceResult<()> {
        self.save_bytes(user_id, filename)
    }
}
