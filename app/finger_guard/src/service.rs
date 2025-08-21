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

//! Implementation of the IFingerGuard service interface.

use crate::aidl;
use crate::crypto::{self, HmacSignable, MapOpenSslErrExt};
use crate::error::{ServiceError, ServiceResult};
use crate::hat::{AuthenticatorType, UnsignedHat, EMPTY_HAT};
use crate::identifiers::{AuthenticatorId, SecureUserId, SensorStateIndex};
use crate::rng;
use crate::time::{Clock, Instant};
use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::{
    AuthenticationResult::AuthenticationResult, EnrollmentResult::EnrollmentResult,
    FinishEnrollSessionResponse::FinishEnrollSessionResponse, HandshakeResponse::HandshakeResponse,
    HardwareAuthToken::HardwareAuthToken, IFingerGuard::IFingerGuard, LockoutStatus::LockoutStatus,
    PrepareAuthSessionResponse::PrepareAuthSessionResponse,
    PrepareEnrollSessionResponse::PrepareEnrollSessionResponse, SensorUserPair::SensorUserPair,
    SessionResponse::SessionResponse,
};
use binder::Interface;
use log::error;
use once_cell::sync::OnceCell;
use std::collections::BTreeMap;
use std::default::Default;
use std::mem;
use std::sync::Mutex;
use std::time::Duration;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
/// Represents the required parameters after the service initializes
/// through the init handshake.
pub struct InitParams {
    pk: crypto::Key,
    tpm_seed: crypto::Secret,
}

/// An interface for all of the interactions that the service has with the trusty environment.
pub trait TrustyEnvironment: Send + Sync + 'static {
    /// Get a reference to the trusty clock.
    fn clock(&self) -> &dyn Clock;
    /// Look up the auth token key from keymint.
    fn get_auth_token_key() -> ServiceResult<crypto::Key>;
    /// Load the init parameters.
    fn load_init_params() -> ServiceResult<InitParams>;
    /// Save the init parameters.
    fn save_init_params(init_params: &InitParams) -> ServiceResult<()>;
    /// Load an authenticator ID.
    fn load_authenticator_id(filename: &str) -> ServiceResult<AuthenticatorId>;
    /// Save an authenticator ID.
    fn save_authenticator_id(auth_id: &AuthenticatorId, filename: &str) -> ServiceResult<()>;
    /// Load a secure user ID.
    fn load_user_id(filename: &str) -> ServiceResult<SecureUserId>;
    /// Save a secure user ID.
    fn save_user_id(user_id: &SecureUserId, filename: &str) -> ServiceResult<()>;
}

#[derive(Clone, PartialOrd, Ord, Eq, PartialEq)]
/// Encapsulates a challenge associated with a SensorStateIndex
pub struct EnrollmentChallenge {
    ssi: SensorStateIndex,
    challenge: i64,
}

impl EnrollmentChallenge {
    const EMPTY: i64 = 0;
    /// Converts the challenge to an i64.
    fn challenge(&self) -> i64 {
        self.challenge
    }
}

#[derive(Default)]
/// Represents the global state of the ongoing sensor session.
enum SensorSession {
    #[default]
    Idle,
    Enroll,
    Auth {
        nonce: crypto::Nonce,
        challenge: i64,
    },
}

/// Implements the `IFingerGuard` AIDL interface for other Trusty apps to call.
pub struct FingerGuardService<T> {
    init_params: Mutex<Option<InitParams>>,
    sk: Mutex<Option<crypto::Key>>,
    sensor_session: Mutex<SensorSession>,
    auth_token_key: OnceCell<crypto::Key>,
    enrollment_challenges: Mutex<BTreeMap<EnrollmentChallenge, Instant>>,
    trusty: T,
}

/// The initial message signed by the private key during the handshake.
struct HandshakeMessage;
impl HmacSignable for HandshakeMessage {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        add_bytes(b"tofu")
    }
}

impl<T: TrustyEnvironment> FingerGuardService<T> {
    /// Construct a new instance of the finger guard service using the given Trusty environment.
    pub fn new(trusty: T) -> Self {
        Self {
            init_params: Mutex::new(
                T::load_init_params()
                    .inspect_err(|e| error!("failed to load init_params: {e:?}"))
                    .ok(),
            ),
            sk: Mutex::new(None),
            sensor_session: Mutex::new(SensorSession::default()),
            auth_token_key: OnceCell::new(),
            enrollment_challenges: Mutex::new(BTreeMap::new()),
            trusty,
        }
    }

    fn get_auth_token_key(&self) -> ServiceResult<&crypto::Key> {
        self.auth_token_key.get_or_try_init(|| T::get_auth_token_key())
    }

    fn init_handshake(&self, client_public_key_bytes: &[u8]) -> ServiceResult<HandshakeResponse> {
        let mut init_params = self
            .init_params
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "init_params", mode: "write" })?;
        if init_params.is_some() {
            return Err(ServiceError::StateAlreadyExists("init_params"));
        }
        let server_private_key = crypto::ec_keygen().wrap_openssl_err("failed to ec keygen")?;
        let server_public_key_bytes = crypto::ec_public_key_serialization(&server_private_key)
            .wrap_openssl_err("failed to serialize server public key")?;
        let pk = crypto::perform_ecdh(server_private_key, client_public_key_bytes)?;
        // generate random tpm_seed.
        let tpm_seed = crypto::Secret::generate();
        let mac = crypto::compute_hmac!(&pk, &HandshakeMessage)?;
        // save pk and tpm_seed to storage.
        let new_init_params = InitParams { pk, tpm_seed };
        T::save_init_params(&new_init_params)?;
        *init_params = Some(new_init_params);
        Ok(aidl::make_handshake_response(server_public_key_bytes, &mac))
    }

    fn new_session(&self, client_nonce: &[u8]) -> ServiceResult<SessionResponse> {
        let client_nonce = crypto::Nonce::import(client_nonce)
            .map_err(|_| ServiceError::InvalidArg("client_nonce"))?;
        let init_params = self
            .init_params
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "init_params", mode: "read" })?;
        let Some(ref init_params) = *init_params else {
            return Err(ServiceError::StateUnavailable("init_params"));
        };
        let mut sk = self
            .sk
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "write" })?;
        if sk.is_some() {
            return Err(ServiceError::StateAlreadyExists("sk"));
        }
        let nonce = crypto::Nonce::generate();
        let new_sk = crypto::compute_hmac!(&init_params.pk, &client_nonce, &nonce)?;
        let iv = crypto::Iv::generate();
        let (wrapped_tpm_seed, tag) = crypto::encrypt_aes256_gcm(
            &new_sk,
            &iv,
            b"tpm_seed", // aad = "tpm_seed"
            &init_params.tpm_seed,
        )
        .wrap_openssl_err("failed to encrypt tpm_seed")?;
        *sk = Some(new_sk.into());
        Ok(aidl::make_session_response(&nonce, wrapped_tpm_seed, &iv, &tag))
    }

    fn generate_challenge(&self, sensor_user_pair: &SensorUserPair) -> ServiceResult<i64> {
        let mut enrollment_challenges = self.enrollment_challenges.try_lock().map_err(|_| {
            ServiceError::LockAcquire { name: "enrollment_challenges", mode: "write" }
        })?;
        let ssi = SensorStateIndex::from(sensor_user_pair);
        let challenge = rng::generate_random_int!(i64);
        let valid_until = self.trusty.clock().now()? + Duration::from_secs(60);
        let ec = EnrollmentChallenge { ssi, challenge };
        enrollment_challenges.insert(ec, valid_until);
        Ok(challenge)
    }

    fn revoke_challenge(
        &self,
        sensor_user_pair: &SensorUserPair,
        challenge: i64,
    ) -> ServiceResult<i64> {
        let mut enrollment_challenges = self.enrollment_challenges.try_lock().map_err(|_| {
            ServiceError::LockAcquire { name: "enrollment_challenges", mode: "write" }
        })?;
        let ssi = SensorStateIndex::from(sensor_user_pair);
        let ec = EnrollmentChallenge { ssi, challenge };
        let now = self.trusty.clock().now()?;
        enrollment_challenges.remove(&ec).map_or(Ok(EnrollmentChallenge::EMPTY), |valid_until| {
            if now < valid_until {
                Ok(ec.challenge())
            } else {
                Ok(EnrollmentChallenge::EMPTY)
            }
        })
    }

    // TODO(b/401303592): Clear sensor lockout with the HAT verification.
    fn prepare_enroll_session(
        &self,
        sensor_user_pair: &SensorUserPair,
        hat: &HardwareAuthToken,
        nonce: &[u8],
    ) -> ServiceResult<PrepareEnrollSessionResponse> {
        let sk = self
            .sk
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "read" })?;
        let Some(ref sk) = *sk else {
            return Err(ServiceError::StateUnavailable("sk"));
        };
        let mut sensor_session = self
            .sensor_session
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "sensor_session", mode: "write" })?;
        if !matches!(*sensor_session, SensorSession::Idle) {
            return Err(ServiceError::StateAlreadyExists("ongoing sensor session"));
        }

        // revoke_challenge returns the given challenge when it is valid.
        let challenge = self.revoke_challenge(sensor_user_pair, hat.challenge)?;
        if challenge == EnrollmentChallenge::EMPTY || challenge != hat.challenge {
            return Err(ServiceError::StateUnavailable("enrollment challenge"));
        }
        // Validate |hat|.
        let auth_token_key = self.get_auth_token_key()?;
        let mac = crypto::compute_hmac!(&auth_token_key, hat)?;
        if mac != hat.mac.as_slice() {
            return Err(ServiceError::BadMac("hardware auth token"));
        }
        // Save the secure user id from the HAT.
        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        let sid_file = sensor_state_index.secure_user_id_file_name();
        let secure_user_id = SecureUserId::from(hat.userId);
        T::save_user_id(&secure_user_id, &sid_file)?;
        // Start a new enroll session.
        let nonce = crypto::Nonce::import(nonce)?;
        let hmac = crypto::sensor_session_message_hmac(
            sk,
            &nonce,
            crypto::MessageSender::FingerGuard,
            crypto::SensorSessionType::Enroll,
            &sensor_state_index,
        )?;
        let response = aidl::make_prepare_enroll_session_response(&hmac);
        *sensor_session = SensorSession::Enroll;
        Ok(response)
    }

    fn finish_enroll_session(
        &self,
        sensor_user_pair: &SensorUserPair,
        result: &EnrollmentResult,
        nonce: &[u8],
    ) -> ServiceResult<FinishEnrollSessionResponse> {
        let sk = self
            .sk
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "read" })?;
        let Some(ref sk) = *sk else {
            return Err(ServiceError::StateUnavailable("sk"));
        };
        let mut sensor_session = self
            .sensor_session
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "sensor_session", mode: "write" })?;
        if !matches!(*sensor_session, SensorSession::Enroll) {
            return Err(ServiceError::StateUnavailable("ongoing enroll session"));
        };
        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        // Close the session.
        let _ = mem::take(&mut *sensor_session);
        // If the enrollment succeeds, compute a sensor message mac with |sensor_challenge|.
        // Otherwise, return an empty response.
        if result.enrolled {
            let nonce = crypto::Nonce::import(nonce)?;
            let hmac = crypto::sensor_session_message_hmac(
                sk,
                &nonce,
                crypto::MessageSender::FingerGuard,
                crypto::SensorSessionType::EnrollFinish,
                &sensor_state_index,
            )?;
            // Generate and save a new AuthenticatorId.
            let authenticator_id = AuthenticatorId::generate_random();
            let file_name = sensor_state_index.authenticator_id_file_name();
            T::save_authenticator_id(&authenticator_id, &file_name)?;
            let response = aidl::make_finish_enroll_session_response(&hmac);
            Ok(response)
        } else {
            Ok(FinishEnrollSessionResponse::default())
        }
    }

    fn prepare_auth_session(
        &self,
        sensor_user_pair: &SensorUserPair,
        challenge: i64,
        nonce: &[u8],
    ) -> ServiceResult<PrepareAuthSessionResponse> {
        let sk = self
            .sk
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "read" })?;
        let Some(ref sk) = *sk else {
            return Err(ServiceError::StateUnavailable("sk"));
        };
        let mut sensor_session = self
            .sensor_session
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "sensor_session", mode: "write" })?;
        if !matches!(*sensor_session, SensorSession::Idle) {
            return Err(ServiceError::StateAlreadyExists("ongoing sensor session"));
        }

        // Start a new auth session.
        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        let nonce = crypto::Nonce::import(nonce)?;
        let hmac = crypto::sensor_session_message_hmac(
            sk,
            &nonce,
            crypto::MessageSender::FingerGuard,
            crypto::SensorSessionType::Auth,
            &sensor_state_index,
        )?;
        let nonce = crypto::Nonce::generate();
        let response = aidl::make_prepare_auth_session_response(&nonce, &hmac);
        *sensor_session = SensorSession::Auth { nonce, challenge };
        Ok(response)
    }

    fn finish_auth_session(
        &self,
        sensor_user_pair: &SensorUserPair,
        result: &AuthenticationResult,
    ) -> ServiceResult<HardwareAuthToken> {
        let sk = self
            .sk
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "read" })?;
        let Some(ref sk) = *sk else {
            return Err(ServiceError::StateUnavailable("sk"));
        };
        let mut sensor_session = self
            .sensor_session
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "sensor_session", mode: "write" })?;
        if !matches!(*sensor_session, SensorSession::Auth { .. }) {
            return Err(ServiceError::StateUnavailable("no ongoing auth session"));
        }
        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        // Close the session.
        let session = mem::take(&mut *sensor_session);
        let SensorSession::Auth { ref nonce, challenge } = session else {
            return Err(ServiceError::StateUnavailable("no ongoing auth session"));
        };
        // If the authentication succeeds, validate the mac is indeed from the sensor.
        if result.authenticated {
            let hmac = crypto::sensor_session_message_hmac(
                sk,
                nonce,
                crypto::MessageSender::Fpmcu,
                crypto::SensorSessionType::Auth,
                &sensor_state_index,
            )?;
            // Use a constant-time comparison to avoid timing attacks against
            // the session hmac. This would be difficult to exploit anyway
            // because retries are not possible, but better safe than sorry.
            if hmac != result.mac.as_slice() {
                return Err(ServiceError::BadMac("authentication result"));
            }
            // Produce a valid HAT signed by the auth token key.
            let auth_token_key = self.get_auth_token_key()?;
            let aid_file_name = sensor_state_index.authenticator_id_file_name();
            let sid_file_name = sensor_state_index.secure_user_id_file_name();
            let authenticator_id = T::load_authenticator_id(&aid_file_name)?;
            let secure_user_id = T::load_user_id(&sid_file_name)?;
            let hat = UnsignedHat::new(
                challenge,
                secure_user_id,
                authenticator_id,
                AuthenticatorType::FINGERPRINT,
                self.trusty.clock().now()?,
            );
            let hat = hat.sign(auth_token_key)?;
            Ok(hat)
            // TODO(b/401303592): Clear sensor lockout state.
        } else {
            Ok(EMPTY_HAT)
        }
    }

    fn read_authenticator_id(
        &self,
        sensor_user_pair: &SensorUserPair,
    ) -> ServiceResult<AuthenticatorId> {
        let index = SensorStateIndex::from(sensor_user_pair);
        let file_name = index.authenticator_id_file_name();
        // Treat read failure as there is no authenticator id and use the default
        // value of 0.
        let authenticator_id = T::load_authenticator_id(&file_name)
            .inspect_err(|e| error!("failed to read authenticator id: {e:?}"))
            .unwrap_or_default();
        Ok(authenticator_id)
    }

    fn generate_authenticator_id(
        &self,
        sensor_user_pair: &SensorUserPair,
    ) -> ServiceResult<AuthenticatorId> {
        let authenticator_id = AuthenticatorId::generate_random();
        let index = SensorStateIndex::from(sensor_user_pair);
        let file_name = index.authenticator_id_file_name();
        T::save_authenticator_id(&authenticator_id, &file_name)?;
        Ok(authenticator_id)
    }
}

// Generically convert a service result into a binder result.
//
// If the result is an error this will also log it as the conversion is lossy and otherwise
// information will be lost.
fn service_result_to_binder_result<T>(
    op_name: &str,
    result: ServiceResult<T>,
) -> binder::Result<T> {
    result.inspect_err(|e| error!("{op_name} failed: {e:?}")).map_err(|e| match e {
        ServiceError::StateAlreadyExists(..) => binder::StatusCode::ALREADY_EXISTS.into(),
        _ => binder::StatusCode::FAILED_TRANSACTION.into(),
    })
}

impl<T: TrustyEnvironment> Interface for FingerGuardService<T> {}

impl<T: TrustyEnvironment> IFingerGuard for FingerGuardService<T> {
    fn initHandshake(&self, client_public_key: &[u8]) -> binder::Result<HandshakeResponse> {
        service_result_to_binder_result(
            "initHandshake",
            Self::init_handshake(self, client_public_key),
        )
    }
    fn newSession(&self, client_nonce: &[u8]) -> binder::Result<SessionResponse> {
        service_result_to_binder_result("newSession", Self::new_session(self, client_nonce))
    }
    fn generateChallenge(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
        service_result_to_binder_result(
            "generateChallenge",
            Self::generate_challenge(self, sensor_user_pair),
        )
    }
    fn revokeChallenge(
        &self,
        sensor_user_pair: &SensorUserPair,
        challenge: i64,
    ) -> binder::Result<i64> {
        service_result_to_binder_result(
            "revokeChallenge",
            Self::revoke_challenge(self, sensor_user_pair, challenge),
        )
    }
    fn prepareEnrollSession(
        &self,
        sensor_user_pair: &SensorUserPair,
        hat: &HardwareAuthToken,
        nonce: &[u8],
    ) -> binder::Result<PrepareEnrollSessionResponse> {
        service_result_to_binder_result(
            "prepareEnrollSession",
            Self::prepare_enroll_session(self, sensor_user_pair, hat, nonce),
        )
    }
    fn finishEnrollSession(
        &self,
        sensor_user_pair: &SensorUserPair,
        result: &EnrollmentResult,
        nonce: &[u8],
    ) -> binder::Result<FinishEnrollSessionResponse> {
        service_result_to_binder_result(
            "finishEnrollSession",
            Self::finish_enroll_session(self, sensor_user_pair, result, nonce),
        )
    }
    fn prepareAuthSession(
        &self,
        sensor_user_pair: &SensorUserPair,
        challenge: i64,
        nonce: &[u8],
    ) -> binder::Result<PrepareAuthSessionResponse> {
        service_result_to_binder_result(
            "prepareAuthSession",
            Self::prepare_auth_session(self, sensor_user_pair, challenge, nonce),
        )
    }
    fn finishAuthSession(
        &self,
        sensor_user_pair: &SensorUserPair,
        result: &AuthenticationResult,
    ) -> binder::Result<HardwareAuthToken> {
        service_result_to_binder_result(
            "finishAuthSession",
            Self::finish_auth_session(self, sensor_user_pair, result),
        )
    }
    fn getAuthenticatorId(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
        service_result_to_binder_result(
            "getAuthenticatorId",
            Self::read_authenticator_id(self, sensor_user_pair).map(|id| id.into()),
        )
    }
    fn newAuthenticatorId(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
        service_result_to_binder_result(
            "newAuthenticatorId",
            Self::generate_authenticator_id(self, sensor_user_pair).map(|id| id.into()),
        )
    }
    // TODO(b/401303592): implement
    fn getLockoutStatus(
        &self,
        _sensor_user_pair: &SensorUserPair,
    ) -> binder::Result<LockoutStatus> {
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }
    // TODO(b/401303592): implement
    fn resetLockout(
        &self,
        _sensor_user_pair: &SensorUserPair,
        _hat: &HardwareAuthToken,
    ) -> binder::Result<()> {
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }
}
