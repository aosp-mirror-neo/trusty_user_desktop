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

//! Provides an implementation of all of the service depenedencies on Trusty.

use crate::clock;
use crate::keymint;
use crate::storage::{PersistedState, SingleFileState};
use finger_guard::crypto;
use finger_guard::error::ServiceResult;
use finger_guard::identifiers::{AuthenticatorId, SecureUserId};
use finger_guard::service::{InitParams, TrustyEnvironment};
use finger_guard::time::Clock;

// Init params are persisted to a single fixed file.
impl PersistedState for InitParams {}
impl SingleFileState for InitParams {
    const FILE_NAME: &str = InitParams::FILE_NAME;
}

// These identifier types support persistence to arbitrary files.
impl PersistedState for AuthenticatorId {}
impl PersistedState for SecureUserId {}

/// An implementation of the trusty environment.
pub struct Trusty;
impl TrustyEnvironment for Trusty {
    fn clock(&self) -> &dyn Clock {
        clock::TRUSTY_CLOCK
    }
    fn get_auth_token_key(&self) -> ServiceResult<crypto::Key> {
        keymint::get_auth_token_key()
    }
    fn load_init_params(&self) -> ServiceResult<InitParams> {
        InitParams::load()
    }
    fn save_init_params(&self, init_params: &InitParams) -> ServiceResult<()> {
        init_params.save()
    }
    fn load_authenticator_id(&self, filename: &str) -> ServiceResult<AuthenticatorId> {
        AuthenticatorId::load_from(filename)
    }
    fn save_authenticator_id(
        &self,
        auth_id: &AuthenticatorId,
        filename: &str,
    ) -> ServiceResult<()> {
        auth_id.save_to(filename)
    }
    fn load_user_id(&self, filename: &str) -> ServiceResult<SecureUserId> {
        SecureUserId::load_from(filename)
    }
    fn save_user_id(&self, user_id: &SecureUserId, filename: &str) -> ServiceResult<()> {
        user_id.save_to(filename)
    }
}
