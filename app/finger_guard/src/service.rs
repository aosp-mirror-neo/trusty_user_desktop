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
use crate::crypto::{self, Hashable, HmacSignable, MapOpenSslErrExt, P256SigVerifier};
use crate::error::{ServiceError, ServiceResult};
use crate::hat::{AuthenticatorType, UnsignedHat, EMPTY_HAT};
use crate::identifiers::{AuthenticatorId, SecureUserId, SensorStateIndex};
use crate::lockout::{self, AuthRateLimiter, MapLockoutStatusErrExt};
use crate::rng;
use crate::sdcp_pki;
use crate::time::{Clock, Instant};
use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::{
    AuthenticationResult::AuthenticationResult, ClientSessionResponse::ClientSessionResponse,
    EnrollmentResult::EnrollmentResult, FinishEnrollSessionResponse::FinishEnrollSessionResponse,
    HardwareAuthToken::HardwareAuthToken, IClientSession::IClientSession,
    IFingerGuard::IFingerGuard, InitResponse::InitResponse, LockoutStatus::LockoutStatus,
    PrepareAuthSessionResponse::PrepareAuthSessionResponse,
    PrepareEnrollSessionResponse::PrepareEnrollSessionResponse, SdcpClaim::SdcpClaim,
    SdcpClientSessionResponse::SdcpClientSessionResponse, SensorUserPair::SensorUserPair,
};
use binder::Interface;
use log::error;
use once_cell::sync::OnceCell;
use std::collections::BTreeMap;
use std::default::Default;
use std::mem;
use std::sync::{Arc, Mutex};
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
impl InitParams {
    /// The name of the file where init parameters should be stored.
    pub const FILE_NAME: &str = "finger_guard_init_params";
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
/// Represents the trusted parameters after the service first establish
/// a SDCP client session.
pub struct SdcpParams {
    device_public_key: crypto::P256Point,
    tpm_seed: crypto::Secret,
}
impl SdcpParams {
    /// The name of the file where SDCP parameters should be stored.
    pub const FILE_NAME: &str = "finger_guard_sdcp_params";
}

/// An interface for all of the interactions that the service has with the trusty environment.
pub trait TrustyEnvironment: Send + Sync + 'static {
    /// Get a reference to the trusty clock.
    fn clock(&self) -> &'static dyn Clock;
    /// Look up the auth token key from keymint.
    fn get_auth_token_key(&self) -> ServiceResult<crypto::Key>;
    /// Load the init parameters.
    fn load_init_params(&self) -> ServiceResult<InitParams>;
    /// Save the init parameters.
    fn save_init_params(&self, init_params: &InitParams) -> ServiceResult<()>;
    /// Load the sdcp parameters.
    fn load_sdcp_params(&self) -> ServiceResult<SdcpParams>;
    /// Save the sdcp parameters.
    fn save_sdcp_params(&self, sdcp_params: &SdcpParams) -> ServiceResult<()>;
    /// Load an authenticator ID.
    fn load_authenticator_id(&self, filename: &str) -> ServiceResult<AuthenticatorId>;
    /// Save an authenticator ID.
    fn save_authenticator_id(&self, auth_id: &AuthenticatorId, filename: &str)
        -> ServiceResult<()>;
    /// Load a secure user ID.
    fn load_user_id(&self, filename: &str) -> ServiceResult<SecureUserId>;
    /// Save a secure user ID.
    fn save_user_id(&self, user_id: &SecureUserId, filename: &str) -> ServiceResult<()>;
}

#[derive(Clone, PartialOrd, Ord, Eq, PartialEq)]
/// Encapsulates a HardwareAuthToken's challenge associated with a SensorStateIndex.
pub struct AuthTokenChallenge {
    ssi: SensorStateIndex,
    challenge: i64,
}

impl AuthTokenChallenge {
    const EMPTY: i64 = 0;
    /// Converts the challenge to an i64.
    fn challenge(&self) -> i64 {
        self.challenge
    }
}

#[derive(Default)]
// Represents the global state of the ongoing sensor session.
enum SensorSession {
    #[default]
    Idle,
    Enroll,
    Auth {
        nonce: crypto::Nonce,
        challenge: i64,
    },
}

// Stores all of the state backing the service. This state is stored separately from the service
// implementation itself so that it can be shared between multiple interfaces.
struct ServiceState<T> {
    init_params: OnceCell<InitParams>,
    sdcp_params: OnceCell<SdcpParams>,
    sensor_session: Mutex<SensorSession>,
    auth_token_key: OnceCell<crypto::Key>,
    enrollment_challenges: Mutex<BTreeMap<AuthTokenChallenge, Instant>>,
    banned_reset_challenges: Mutex<BTreeMap<AuthTokenChallenge, Instant>>,
    auth_rate_limiters: Mutex<BTreeMap<SensorStateIndex, AuthRateLimiter>>,
    trusty: T,
}

// Helper macro that will lock the specified set of fields on service state.
//
// If any of the lock acquisitions fail this will return an Err(ServiceError::LockAcquire). The
// intent is for this macro to be used within an interface implementation function that returns
// ServiceResult to produce the snippet of code used to lock any state functions.
macro_rules! lock_state {
    ($state:expr, $($field:ident),+) => {
        {
            let state = &($state);
            $(
            let $field = state
                .$field
                .try_lock()
                .map_err(|_| ServiceError::LockAcquire(stringify!($field)))?;
            )+
            // Note that this evaluates to single value for 1 field, a tuple for 2+ fields.
            ($($field),+)
        }
    };
}

impl<T: TrustyEnvironment> ServiceState<T> {
    fn get_auth_token_key(&self) -> ServiceResult<&crypto::Key> {
        self.auth_token_key.get_or_try_init(|| self.trusty.get_auth_token_key())
    }

    fn create_default_arl(&self) -> ServiceResult<AuthRateLimiter> {
        AuthRateLimiter::new(
            self.trusty.clock(),
            lockout::DEFAULT_AUTH_TIMEOUT_WINDOW,
            lockout::DEFAULT_DELAY_POLICY.to_vec(),
        )
    }
}

// Represents a client session.
//
// Note that this is distinct from a sensor session, which has a shorter lifetime. Client sessions
// are expected to be started by a client when it first connects to the service and are not normally
// terminated unless the client shuts down.
struct ClientSession<T> {
    state: Arc<ServiceState<T>>,
    sk: crypto::Key,
}

impl<T: TrustyEnvironment> ClientSession<T> {
    fn prepare_enroll_session(
        &self,
        sensor_user_pair: &SensorUserPair,
        hat: &HardwareAuthToken,
        nonce: crypto::Nonce,
    ) -> ServiceResult<PrepareEnrollSessionResponse> {
        let (mut sensor_session, mut enrollment_challenges) =
            lock_state!(self.state, sensor_session, enrollment_challenges);
        if !matches!(*sensor_session, SensorSession::Idle) {
            return Err(ServiceError::StateAlreadyExists("ongoing sensor session"));
        }
        // Check the HAT's challenge is still valid.
        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        let ec = AuthTokenChallenge { ssi: sensor_state_index, challenge: hat.challenge };
        let now = self.state.trusty.clock().now()?;
        enrollment_challenges.retain(|_, valid_until| now <= *valid_until);
        if !enrollment_challenges.contains_key(&ec) {
            return Err(ServiceError::StateUnavailable("enrollment challenge"));
        }
        // Validate |hat|.
        let auth_token_key = self.state.get_auth_token_key()?;
        let mac = crypto::compute_hmac!(&auth_token_key, hat)?;
        if mac != hat.mac.as_slice() {
            // revoke the challenge of invalid |hat| so there is no retry for mac enumeration.
            let _ = enrollment_challenges.remove(&ec);
            return Err(ServiceError::BadMac("hardware auth token"));
        }
        // Save the secure user id from the HAT.
        let sid_file = sensor_state_index.secure_user_id_file_name();
        let secure_user_id = SecureUserId::from(hat.userId);
        self.state.trusty.save_user_id(&secure_user_id, &sid_file)?;
        // Start a new enroll session.
        let hmac = crypto::sensor_session_message_hmac(
            &self.sk,
            &nonce,
            crypto::MessageSender::FingerGuard,
            crypto::SensorSessionType::Enroll,
            &sensor_state_index,
        )?;
        *sensor_session = SensorSession::Enroll;
        Ok(PrepareEnrollSessionResponse::from(hmac))
    }

    fn finish_enroll_session(
        &self,
        sensor_user_pair: &SensorUserPair,
        result: &EnrollmentResult,
        nonce: crypto::Nonce,
    ) -> ServiceResult<FinishEnrollSessionResponse> {
        let (mut sensor_session, mut auth_rate_limiters) =
            lock_state!(self.state, sensor_session, auth_rate_limiters);
        if !matches!(*sensor_session, SensorSession::Enroll) {
            return Err(ServiceError::StateUnavailable("ongoing enroll session"));
        };
        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        // Close the session.
        let _ = mem::take(&mut *sensor_session);
        // If the enrollment succeeds, compute a sensor message mac with |sensor_challenge|.
        // Otherwise, return an empty response.
        if result.enrolled {
            let hmac = crypto::sensor_session_message_hmac(
                &self.sk,
                &nonce,
                crypto::MessageSender::FingerGuard,
                crypto::SensorSessionType::EnrollFinish,
                &sensor_state_index,
            )?;
            // Generate and save a new AuthenticatorId.
            let authenticator_id = AuthenticatorId::generate_random();
            let file_name = sensor_state_index.authenticator_id_file_name();
            self.state.trusty.save_authenticator_id(&authenticator_id, &file_name)?;
            // Create a new auth limiter and keep it in the memory.
            let arl = self.state.create_default_arl()?;
            auth_rate_limiters.insert(sensor_state_index, arl);
            Ok(FinishEnrollSessionResponse::from(hmac))
        } else {
            Ok(FinishEnrollSessionResponse::default())
        }
    }

    fn prepare_auth_session(
        &self,
        sensor_user_pair: &SensorUserPair,
        challenge: i64,
        nonce: crypto::Nonce,
    ) -> ServiceResult<PrepareAuthSessionResponse> {
        let (mut sensor_session, mut auth_rate_limiters) =
            lock_state!(self.state, sensor_session, auth_rate_limiters);
        if !matches!(*sensor_session, SensorSession::Idle) {
            return Err(ServiceError::StateAlreadyExists("ongoing sensor session"));
        }
        // Record the attempt with the auth rate limiter then start a new auth session.
        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        let arl = auth_rate_limiters
            .get_mut(&sensor_state_index)
            .ok_or(ServiceError::StateUnavailable("auth rate limiter"))?;
        // If the attempt is not rate limited, the current attempt count is returned and
        // ignored for now.
        let _ = arl.increment_attempt_counter().wrap_lockout_status_err()?;
        let hmac = crypto::sensor_session_message_hmac(
            &self.sk,
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
        let (mut sensor_session, mut auth_rate_limiters) =
            lock_state!(self.state, sensor_session, auth_rate_limiters);
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
                &self.sk,
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
            // Get the auth rate limiter and clear the counter.
            let arl = auth_rate_limiters
                .get_mut(&sensor_state_index)
                .ok_or(ServiceError::StateUnavailable("auth rate limiter"))?;
            arl.reset_attempt_counter();

            // Produce a valid HAT signed by the auth token key.
            let auth_token_key = self.state.get_auth_token_key()?;
            let aid_file_name = sensor_state_index.authenticator_id_file_name();
            let sid_file_name = sensor_state_index.secure_user_id_file_name();
            let authenticator_id = self.state.trusty.load_authenticator_id(&aid_file_name)?;
            let secure_user_id = self.state.trusty.load_user_id(&sid_file_name)?;
            let hat = UnsignedHat::new(
                challenge,
                secure_user_id,
                authenticator_id,
                AuthenticatorType::FINGERPRINT,
                self.state.trusty.clock().now()?,
            );
            let hat = hat.sign(auth_token_key)?;
            Ok(hat)
        } else {
            Ok(EMPTY_HAT)
        }
    }
}

impl<T: TrustyEnvironment> Interface for ClientSession<T> {}

impl<T: TrustyEnvironment> IClientSession for ClientSession<T> {
    fn prepareEnrollSession(
        &self,
        sensor_user_pair: &SensorUserPair,
        hat: &HardwareAuthToken,
        nonce: &[u8; 32],
    ) -> binder::Result<PrepareEnrollSessionResponse> {
        service_result_to_binder_result(
            "prepareEnrollSession",
            Self::prepare_enroll_session(self, sensor_user_pair, hat, nonce.into()),
        )
    }
    fn finishEnrollSession(
        &self,
        sensor_user_pair: &SensorUserPair,
        result: &EnrollmentResult,
        nonce: &[u8; 32],
    ) -> binder::Result<FinishEnrollSessionResponse> {
        service_result_to_binder_result(
            "finishEnrollSession",
            Self::finish_enroll_session(self, sensor_user_pair, result, nonce.into()),
        )
    }
    fn prepareAuthSession(
        &self,
        sensor_user_pair: &SensorUserPair,
        challenge: i64,
        nonce: &[u8; 32],
    ) -> binder::Result<PrepareAuthSessionResponse> {
        service_result_to_binder_result(
            "prepareAuthSession",
            Self::prepare_auth_session(self, sensor_user_pair, challenge, nonce.into()),
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
}

/// Implements the `IFingerGuard` AIDL interface for other Trusty apps to call.
pub struct FingerGuardService<T> {
    state: Arc<ServiceState<T>>,
}

/// The initial message signed by the private key during the pk handshake.
struct HandshakeMessage;
impl HmacSignable for HandshakeMessage {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        add_bytes(b"tofu")
    }
}

// The 2-byte header for generating the hash which the firmware signature in the sdcp claim is signed on.
struct SdcpHashHeader;
impl Hashable for SdcpHashHeader {
    fn update(&self, mut add_bytes: impl FnMut(&[u8])) {
        add_bytes(&[0xc0, 0x01])
    }
}

/// The context string appended to nonces during SDCP session key derivation.
struct SdcpContext;
impl HmacSignable for SdcpContext {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        add_bytes(b"sdcp")
    }
}

impl<T: TrustyEnvironment> FingerGuardService<T> {
    /// Construct a new instance of the finger guard service using the given Trusty environment.
    pub fn new(trusty: T) -> Self {
        Self {
            state: Arc::new(ServiceState {
                init_params: OnceCell::new(),
                sdcp_params: OnceCell::new(),
                sensor_session: Default::default(),
                auth_token_key: Default::default(),
                enrollment_challenges: Default::default(),
                banned_reset_challenges: Default::default(),
                auth_rate_limiters: Default::default(),
                trusty,
            }),
        }
    }

    fn get_init_params(&self) -> Option<&InitParams> {
        self.state
            .init_params
            .get_or_try_init(|| {
                self.state
                    .trusty
                    .load_init_params()
                    .inspect_err(|e| error!("failed to load init_params: {e:?}"))
            })
            .ok()
    }

    fn get_sdcp_params(&self) -> Option<&SdcpParams> {
        self.state
            .sdcp_params
            .get_or_try_init(|| {
                self.state
                    .trusty
                    .load_sdcp_params()
                    .inspect_err(|e| error!("failed to load sdcp_params: {e:?}"))
            })
            .ok()
    }

    fn init_handshake(&self, client_public_key: crypto::P256Point) -> ServiceResult<InitResponse> {
        // Fetch the existing init params, or generate a fresh set of them if none exist. The
        // response will only be populated if the get_or_try_init does a new handshake.
        let mut response = None;
        self.state.init_params.get_or_try_init(|| {
            // Try to load any existing stored init params first.
            if let Ok(init_params) = self.state.trusty.load_init_params() {
                // Note that we do not set `response` here because having pre-existing parameters
                // is a success for initializing init_params, but a failure for init_handshake.
                return Ok(init_params);
            }
            // Generate a fresh public+private key pair.
            let server_private_key = crypto::ec_keygen().wrap_openssl_err("failed to ec keygen")?;
            let server_public_key = crypto::ec_public_key_serialization(&server_private_key)
                .wrap_openssl_err("failed to serialize server public key")?;
            // Use our new server key to do a DH exchange with the client public key.
            let pk = crypto::perform_ecdh(server_private_key, &client_public_key)?;
            let mac = crypto::compute_hmac!(&pk, &HandshakeMessage)?;
            // Save the newly generated PK along with a new TPM seed out to storage.
            let init_params = InitParams { pk, tpm_seed: crypto::Secret::generate() };
            self.state.trusty.save_init_params(&init_params)?;
            // If we get here we have saved a new handshake, create the response to return.
            response = Some(aidl::make_init_response(&server_public_key, &mac));
            Ok(init_params)
        })?;
        response.ok_or(ServiceError::StateAlreadyExists("init_params"))
    }

    fn create_client_session(
        &self,
        client_nonce: crypto::Nonce,
    ) -> ServiceResult<ClientSessionResponse> {
        // let client_nonce = crypto::Nonce::from(client_nonce);
        let Some(init_params) = self.get_init_params() else {
            return Err(ServiceError::StateUnavailable("init_params"));
        };
        // Reject non-sdcp session creation if an SDCP session has been established.
        if self.get_sdcp_params().is_some() {
            return Err(ServiceError::StateAlreadyExists("sdcp_params"));
        }
        let nonce = crypto::Nonce::generate();
        let new_sk = crypto::compute_hmac!(&init_params.pk, &client_nonce, &nonce)?;
        let iv = crypto::Iv::generate();
        let (wrapped_tpm_seed, tag) = crypto::encrypt_aes256_gcm(
            &new_sk,
            &iv,
            b"tpm_seed", // aad = "tpm_seed"
            &init_params.tpm_seed,
        )?;
        let client_session = ClientSession { state: Arc::clone(&self.state), sk: new_sk.into() };
        let session_response = aidl::make_client_session_response(
            &nonce,
            &wrapped_tpm_seed,
            &iv,
            &tag,
            Some(client_session),
        );
        Ok(session_response)
    }

    fn create_sdcp_client_session(
        &self,
        sdcp_claim: &SdcpClaim,
    ) -> ServiceResult<SdcpClientSessionResponse> {
        // TODO(b/451630059): consider to pin firmware hash in SdcpParams so we don't need to
        // maintain an allowlist of possible firmware hash values.
        if self.get_init_params().is_some() {
            return Err(ServiceError::StateAlreadyExists("init_params"));
        }
        let model_key = crypto::P256Point::from(&sdcp_claim.modelPublicKey);
        let model_key_sig = crypto::P256Sig::from(&sdcp_claim.modelKeySignature);
        if !sdcp_pki::verify_public_key_signature(&model_key, &model_key_sig)? {
            return Err(ServiceError::InvalidArg("sdcp model key signature"));
        }
        let device_key = crypto::P256Point::from(&sdcp_claim.devicePublicKey);
        let device_key_sig = crypto::P256Sig::from(&sdcp_claim.deviceKeySignature);
        if !model_key.verify(&crypto::compute_sha256!(&device_key), &device_key_sig)? {
            return Err(ServiceError::InvalidArg("sdcp device key signature"));
        }
        let firmware_hash = crypto::HashValue::from(&sdcp_claim.firmwareHash);
        let ephemeral_public_key = crypto::P256Point::from(&sdcp_claim.ephemeralPublicKey);
        let firmware_sig = crypto::P256Sig::from(&sdcp_claim.firmwareSignature);
        if !device_key.verify(
            &crypto::compute_sha256!(&SdcpHashHeader, &firmware_hash, &ephemeral_public_key),
            &firmware_sig,
        )? {
            return Err(ServiceError::InvalidArg("sdcp firmware signature"));
        }

        let sdcp_params = self.state.sdcp_params.get_or_try_init(|| {
            let device_public_key = crypto::P256Point::from(&sdcp_claim.devicePublicKey);
            // Save the device public key along with a new TPM seed out to storage.
            let sdcp_params =
                SdcpParams { device_public_key, tpm_seed: crypto::Secret::generate() };
            self.state.trusty.save_sdcp_params(&sdcp_params)?;
            Ok(sdcp_params)
        })?;
        if sdcp_params.device_public_key != &sdcp_claim.devicePublicKey {
            return Err(ServiceError::StateAlreadyExists("inconsistent device key"));
        }
        let client_nonce = crypto::Nonce::from(&sdcp_claim.nonce);
        let nonce = crypto::Nonce::generate();
        // Generate a fresh public+private key pair.
        let server_private_key = crypto::ec_keygen().wrap_openssl_err("failed to ec keygen")?;
        let server_public_key = crypto::ec_public_key_serialization(&server_private_key)
            .wrap_openssl_err("failed to serialize server public key")?;
        // Use our new server key to do a DH exchange with the client's ephemeral public key.
        let pk = crypto::perform_ecdh(server_private_key, &ephemeral_public_key)?;
        let new_sk = crypto::compute_hmac!(&pk, &client_nonce, &nonce, &SdcpContext)?;
        let iv = crypto::Iv::generate();
        let (wrapped_tpm_seed, tag) = crypto::encrypt_aes256_gcm(
            &new_sk,
            &iv,
            b"tpm_seed", // aad = "tpm_seed"
            &sdcp_params.tpm_seed,
        )?;
        let client_session = ClientSession { state: Arc::clone(&self.state), sk: new_sk.into() };
        let session_response = aidl::make_sdcp_client_session_response(
            &server_public_key,
            &nonce,
            &wrapped_tpm_seed,
            &iv,
            &tag,
            Some(client_session),
        );
        Ok(session_response)
    }

    fn generate_challenge(&self, sensor_user_pair: &SensorUserPair) -> ServiceResult<i64> {
        let mut enrollment_challenges = lock_state!(self.state, enrollment_challenges);
        let ssi = SensorStateIndex::from(sensor_user_pair);
        let challenge = rng::generate_random_int!(i64);
        let valid_until = self.state.trusty.clock().now()? + Duration::from_secs(60);
        let ec = AuthTokenChallenge { ssi, challenge };
        enrollment_challenges.insert(ec, valid_until);
        Ok(challenge)
    }

    fn revoke_challenge(
        &self,
        sensor_user_pair: &SensorUserPair,
        challenge: i64,
    ) -> ServiceResult<i64> {
        let mut enrollment_challenges = lock_state!(self.state, enrollment_challenges);
        let ssi = SensorStateIndex::from(sensor_user_pair);
        let ec = AuthTokenChallenge { ssi, challenge };
        let now = self.state.trusty.clock().now()?;
        enrollment_challenges.remove(&ec).map_or(Ok(AuthTokenChallenge::EMPTY), |valid_until| {
            if now < valid_until {
                Ok(ec.challenge())
            } else {
                Ok(AuthTokenChallenge::EMPTY)
            }
        })
    }

    fn read_authenticator_id(
        &self,
        sensor_user_pair: &SensorUserPair,
    ) -> ServiceResult<AuthenticatorId> {
        let index = SensorStateIndex::from(sensor_user_pair);
        let file_name = index.authenticator_id_file_name();
        // Treat read failure as there is no authenticator id and use the default
        // value of 0.
        let authenticator_id = self
            .state
            .trusty
            .load_authenticator_id(&file_name)
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
        self.state.trusty.save_authenticator_id(&authenticator_id, &file_name)?;
        Ok(authenticator_id)
    }

    fn get_lockout_status(
        &self,
        sensor_user_pair: &SensorUserPair,
    ) -> ServiceResult<LockoutStatus> {
        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        let auth_rate_limiters = lock_state!(self.state, auth_rate_limiters);

        // Clear the auth rate limiter counter.
        let Some(arl) = auth_rate_limiters.get(&sensor_state_index) else {
            // When the rate limiter is not found, either there is no previous enrollment,
            // or the TA is freshly rebooted and requiring a knowledge factor authentiction.
            // Either case, return PermanentLockout.
            return Ok(LockoutStatus::PermanentLockout(true));
        };
        let status = match arl.get_lockout_status() {
            None => LockoutStatus::Available(true),
            // If the clock is not available, the rate limiter fail closed
            Some(lockout::LockoutStatus::Unknown) => LockoutStatus::PermanentLockout(true),
            Some(lockout::LockoutStatus::Permanent) => LockoutStatus::PermanentLockout(true),
            Some(lockout::LockoutStatus::Timed(duration)) => LockoutStatus::TimedLockoutMillis(
                i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
            ),
        };
        Ok(status)
    }

    fn reset_lockout(
        &self,
        sensor_user_pair: &SensorUserPair,
        hat: &HardwareAuthToken,
    ) -> ServiceResult<()> {
        // Check |hat| is recently minted, at most one minutes old.
        static SHELF_LIFE: Duration = Duration::from_secs(60);
        let (mut banned_reset_challenges, mut auth_rate_limiters) =
            lock_state!(self.state, banned_reset_challenges, auth_rate_limiters);

        let now = self.state.trusty.clock().now()?;
        let hat_minted_at = Instant::from(hat);
        if now > hat_minted_at + SHELF_LIFE {
            return Err(ServiceError::InvalidArg("Stale hardware auth token"));
        }
        // Check |hat| contains a unique challenge, while allowing valid |hat|s to be reused.
        // Reject any retried invalid HAT before HMAC computation.
        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        let reset_challenge =
            AuthTokenChallenge { ssi: sensor_state_index, challenge: hat.challenge };
        banned_reset_challenges.retain(|_, minted_at| now <= *minted_at + SHELF_LIFE);
        if banned_reset_challenges.contains_key(&reset_challenge) {
            return Err(ServiceError::InvalidArg("Reused hardware auth token challenge"));
        }
        // Validate |hat|.
        let auth_token_key = self.state.get_auth_token_key()?;
        let mac = crypto::compute_hmac!(&auth_token_key, hat)?;
        if mac != hat.mac.as_slice() {
            // Only record challenges from invalid hats.
            banned_reset_challenges.insert(reset_challenge, hat_minted_at);
            return Err(ServiceError::BadMac("hardware auth token"));
        }
        // Decide the reset behavior based on the |hat|'s authenticator type:
        //     1. Password.
        //        A knowledge factor (i.e. stronger factor) has been used. Both the
        //        attempt counter and the timeout time needs reset --> a new rate limiter is
        //        created.
        //     2. Fingerprint (or another biometrics authenticator type value in the future).
        //        Only reset the attempt counter. --> an existing rate limiter is required, and
        //        only reset its attempt counter.
        let auth_type = AuthenticatorType::from(hat);
        match auth_type {
            AuthenticatorType::PASSWORD => {
                auth_rate_limiters.insert(sensor_state_index, self.state.create_default_arl()?);
            }
            AuthenticatorType::FINGERPRINT => {
                let arl = auth_rate_limiters
                    .get_mut(&sensor_state_index)
                    .ok_or(ServiceError::StateUnavailable("auth rate limiter"))?;
                arl.reset_attempt_counter();
            }
            _ => {
                return Err(ServiceError::InvalidArg(
                    "Invalid hardware auth token authenticator type",
                ));
            }
        }
        Ok(())
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
    fn init(&self, client_public_key: &[u8]) -> binder::Result<InitResponse> {
        service_result_to_binder_result(
            "init",
            Self::init_handshake(
                self,
                client_public_key.try_into().map_err(|e| {
                    error!("init failed: {e:?}");
                    binder::Status::from(binder::StatusCode::BAD_VALUE)
                })?,
            ),
        )
    }
    fn createClientSession(
        &self,
        client_nonce: &[u8; 32],
    ) -> binder::Result<ClientSessionResponse> {
        service_result_to_binder_result(
            "createClientSession",
            Self::create_client_session(self, client_nonce.into()),
        )
    }
    fn createSdcpClientSession(
        &self,
        sdcp_claim: &SdcpClaim,
    ) -> binder::Result<SdcpClientSessionResponse> {
        service_result_to_binder_result(
            "createSdcpClientSession",
            Self::create_sdcp_client_session(self, sdcp_claim),
        )
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
    fn getLockoutStatus(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<LockoutStatus> {
        service_result_to_binder_result(
            "getLockoutStatus",
            Self::get_lockout_status(self, sensor_user_pair),
        )
    }
    fn resetLockout(
        &self,
        sensor_user_pair: &SensorUserPair,
        hat: &HardwareAuthToken,
    ) -> binder::Result<()> {
        service_result_to_binder_result(
            "resetLockout",
            Self::reset_lockout(self, sensor_user_pair, hat),
        )
    }
}

#[cfg(test)]
mod test {
    use super::{FingerGuardService, SdcpContext, SdcpHashHeader};
    use crate::aidl;
    use crate::crypto;
    use crate::error::ServiceResult;
    use crate::fake::{SimulatedClock, SimulatedTrusty};
    use crate::hat::{AuthenticatorType, UnsignedHat};
    use crate::identifiers::{AuthenticatorId, SecureUserId};
    use crate::lockout;
    use crate::rng;
    use crate::service::{InitParams, TrustyEnvironment};
    use crate::time::{Clock, Instant};
    use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::{
        AuthenticationResult::AuthenticationResult, EnrollmentResult::EnrollmentResult,
        IClientSession::IClientSession, LockoutStatus::LockoutStatus, SdcpClaim::SdcpClaim,
        SensorUserPair::SensorUserPair,
    };
    use binder::Strong;
    use openssl::ec::EcKey;
    use openssl::pkey::Private;
    use std::array;
    use std::time::Duration;
    use zerocopy::{FromBytes, IntoBytes};

    struct SdcpClientState {
        model_public_key: crypto::P256Point,
        model_key_sig: crypto::P256Sig,
        device_private_key: EcKey<Private>,
        device_public_key: crypto::P256Point,
        device_key_sig: crypto::P256Sig,
        firmware_hash: crypto::HashValue,
    }

    impl SdcpClientState {
        fn new() -> Self {
            let model_private_key = crypto::ec_keygen().unwrap();
            let model_public_key = crypto::ec_public_key_serialization(&model_private_key).unwrap();
            //  Self-signed model key is accepted for unit tests.
            let model_key_sig =
                crypto::ecdsa_sign(&crypto::compute_sha256!(&model_public_key), &model_private_key)
                    .unwrap();
            let device_private_key = crypto::ec_keygen().unwrap();
            let device_public_key =
                crypto::ec_public_key_serialization(&device_private_key).unwrap();
            let device_key_sig = crypto::ecdsa_sign(
                &crypto::compute_sha256!(&device_public_key),
                &model_private_key,
            )
            .unwrap();
            let firmware_hash_bytes = rng::generate_random_buffer::<32>();
            let firmware_hash = crypto::HashValue::from(&firmware_hash_bytes);
            Self {
                model_public_key,
                model_key_sig,
                device_private_key,
                device_public_key,
                device_key_sig,
                firmware_hash,
            }
        }
        // Generate a SdcpClaim and the ephemeral private key for session establishment.
        fn generate_sdcp_claim(&self) -> (SdcpClaim, EcKey<Private>) {
            let ephemeral_private_key = crypto::ec_keygen().unwrap();
            let ephemeral_public_key =
                crypto::ec_public_key_serialization(&ephemeral_private_key).unwrap();
            let client_nonce_bytes = rng::generate_random_buffer::<32>();
            let client_nonce = crypto::Nonce::from(&client_nonce_bytes);
            let firmware_sig = crypto::ecdsa_sign(
                &crypto::compute_sha256!(
                    &SdcpHashHeader,
                    &self.firmware_hash,
                    &ephemeral_public_key
                ),
                &self.device_private_key,
            )
            .unwrap();
            (
                aidl::make_sdcp_claim(
                    &client_nonce,
                    &self.model_public_key,
                    &self.model_key_sig,
                    &self.device_public_key,
                    &self.device_key_sig,
                    &ephemeral_public_key,
                    &self.firmware_hash,
                    &firmware_sig,
                ),
                ephemeral_private_key,
            )
        }
    }

    // Setup a service with a random auth_token_key and carried out a simulated client
    // session establishment with the service, returns the simulated clock, the service, the auth
    // token key, the client session instance, and the channel key.
    fn service_setup() -> (
        &'static SimulatedClock,
        FingerGuardService<SimulatedTrusty>,
        crypto::Key,
        Strong<dyn IClientSession>,
        crypto::Key,
    ) {
        let auth_token_key_bytes = rng::generate_random_vec::<32>();
        let auth_token_key = crypto::Key::read_from_bytes(&auth_token_key_bytes).unwrap();
        let init_params = InitParams {
            pk: crypto::Key::read_from_bytes(&array::from_fn::<_, 32, _>(|x| x as u8 + 1)).unwrap(),
            tpm_seed: crypto::Secret::read_from_bytes(&array::from_fn::<_, 32, _>(|x| x as u8 + 2))
                .unwrap(),
        };
        let trusty = SimulatedTrusty::new();
        trusty.set_auth_token_key(&auth_token_key);
        trusty.save_init_params(&init_params).unwrap();
        let clock = trusty.simulated_clock();
        let service = FingerGuardService::new(trusty);

        let client_nonce_bytes = rng::generate_random_buffer::<32>();
        let client_nonce = crypto::Nonce::from(&client_nonce_bytes);
        let client_session_response =
            service.create_client_session((&client_nonce_bytes).into()).unwrap();
        let server_nonce = crypto::Nonce::from(&client_session_response.nonce);
        let sk = crypto::compute_hmac!(&init_params.pk, &client_nonce, &server_nonce).unwrap();

        // Decrypt the wrapped tpm seed, AEAD ensures the decryption succeeds and outputs only
        // the correct plaintext.
        let iv = crypto::Iv::read_from_bytes(client_session_response.iv.as_slice()).unwrap();
        let tag =
            crypto::Aes256Tag::read_from_bytes(client_session_response.tag.as_slice()).unwrap();
        let encrypted_tpm_seed = crypto::WrappedSecret::read_from_bytes(
            client_session_response.wrappedTpmSeed.as_slice(),
        )
        .unwrap();
        let aad = b"tpm_seed";
        let _ = crypto::decrypt_aes256_gcm(&sk, &iv, aad, &encrypted_tpm_seed, &tag).unwrap();

        // Convert the HMAC into a key.
        let sk = crypto::Key::from(sk);
        (clock, service, auth_token_key, client_session_response.clientSession.unwrap(), sk)
    }

    // Setup a service with a random auth_token_key and carried out the first SDCP
    // session establishment with the service, returns the simulated clock, the service, the auth
    // token key, and the client state for subsequent SDCP session creations.
    fn service_sdcp_session_setup(
    ) -> (&'static SimulatedClock, FingerGuardService<SimulatedTrusty>, crypto::Key, SdcpClientState)
    {
        let auth_token_key_bytes = rng::generate_random_vec::<32>();
        let auth_token_key = crypto::Key::read_from_bytes(&auth_token_key_bytes).unwrap();
        let trusty = SimulatedTrusty::new();
        trusty.set_auth_token_key(&auth_token_key);
        let clock = trusty.simulated_clock();
        let service = FingerGuardService::new(trusty);

        let sdcp_client_state = SdcpClientState::new();
        let (sdcp_claim, ephemeral_private_key) = sdcp_client_state.generate_sdcp_claim();
        let client_session_response = service.create_sdcp_client_session(&sdcp_claim).unwrap();
        let client_nonce = crypto::Nonce::from(&sdcp_claim.nonce);
        let server_nonce = crypto::Nonce::from(&client_session_response.nonce);
        let server_public_key = crypto::P256Point::from(&client_session_response.serverPublicKey);
        let pk = crypto::perform_ecdh(ephemeral_private_key, &server_public_key).unwrap();
        let sk = crypto::compute_hmac!(&pk, &client_nonce, &server_nonce, &SdcpContext).unwrap();

        // Decrypt the wrapped tpm seed, AEAD ensures the decryption succeeds and outputs only
        // the correct plaintext.
        let iv = crypto::Iv::read_from_bytes(client_session_response.iv.as_slice()).unwrap();
        let tag =
            crypto::Aes256Tag::read_from_bytes(client_session_response.tag.as_slice()).unwrap();
        let encrypted_tpm_seed = crypto::WrappedSecret::read_from_bytes(
            client_session_response.wrappedTpmSeed.as_slice(),
        )
        .unwrap();
        let aad = b"tpm_seed";
        let _ = crypto::decrypt_aes256_gcm(&sk, &iv, aad, &encrypted_tpm_seed, &tag).unwrap();
        (clock, service, auth_token_key, sdcp_client_state)
    }

    // Struct used in tests to allow arbitrary blobs to be supplied to the HMAC generator.
    struct TestBlob<'a>(&'a [u8]);
    impl<'a> crypto::HmacSignable for TestBlob<'a> {
        fn update(
            &self,
            mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>,
        ) -> ServiceResult<()> {
            add_bytes(self.0)
        }
    }

    #[test]
    fn test_no_auth_token_key() {
        let trusty = SimulatedTrusty::new();
        let service = FingerGuardService::new(trusty);
        assert!(service.state.get_auth_token_key().is_err());
    }

    #[test]
    fn test_auth_token_key() {
        let key_bytes: [u8; 32] = array::from_fn(|x| x as u8);
        let trusty = SimulatedTrusty::new();
        trusty.set_auth_token_key(&crypto::Key::read_from_bytes(&key_bytes).unwrap());
        let service = FingerGuardService::new(trusty);
        let out_key = service.state.get_auth_token_key().unwrap();
        assert_eq!(out_key.as_bytes(), key_bytes);
    }

    #[test]
    fn test_service_setup() {
        let _ = service_setup();
    }

    #[test]
    fn test_multi_client_session_setup() {
        let (_, service, _, _, _) = service_setup();
        let client_nonce_bytes = rng::generate_random_buffer::<32>();
        let _ = service.create_client_session((&client_nonce_bytes).into()).unwrap();
    }

    #[test]
    fn test_enrollment_challenges() {
        let (_, service, _, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        // Generate multiple challenges and revoke them individually.
        let c1 = service.generate_challenge(&sup).unwrap();
        assert_ne!(c1, 0_i64);
        let c2 = service.generate_challenge(&sup).unwrap();
        assert_ne!(c2, 0_i64);
        assert_ne!(c1, c2);
        // Revoke once, return the same challenge.
        let revoked_c1 = service.revoke_challenge(&sup, c1).unwrap();
        assert_eq!(c1, revoked_c1);
        let revoked_c2 = service.revoke_challenge(&sup, c2).unwrap();
        assert_eq!(c2, revoked_c2);
        // Revoke the 1st challenge twice, return zero.
        assert_eq!(service.revoke_challenge(&sup, c1).unwrap(), 0);
        // Revoke some randome challenge, return zero.
        assert_eq!(service.revoke_challenge(&sup, 1234_i64).unwrap(), 0);
    }

    #[test]
    fn test_authenticator_id() {
        let (_, service, _, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let id = service.generate_authenticator_id(&sup).unwrap();
        assert_ne!(i64::from(id), 0);
        let got_id = service.read_authenticator_id(&sup).unwrap();
        assert_eq!(id, got_id);
    }

    #[test]
    fn test_prepare_enrollment() {
        let (_, service, auth_token_key, client_session, sk) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let session_resp = client_session.prepareEnrollSession(&sup, &hat, &nonce).unwrap();
        let hmac = crypto::compute_hmac!(
            &sk,
            &TestBlob(&nonce),
            &TestBlob(&sup.userId.to_le_bytes()),
            &TestBlob(b"finger_guardenroll")
        )
        .unwrap();
        assert!(hmac == session_resp.mac.as_slice());
    }

    #[test]
    fn test_prepare_enrollment_rejects_bad_challange() {
        let (_, _, auth_token_key, client_session, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            0, // Bad challange value
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        assert!(client_session.prepareEnrollSession(&sup, &hat, &nonce).is_err());
    }

    #[test]
    fn test_prepare_enrollment_invalidate_challenge_in_invalid_hat() {
        let (_, service, _, client_session, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let challenge = service.generate_challenge(&sup).unwrap();
        assert_ne!(challenge, 0_i64);
        let hat = UnsignedHat::new(
            challenge,
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let fake_key = crypto::Key::read_from_bytes(&[0; 32]).unwrap();
        let fake_hat = hat.sign(&fake_key).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        assert!(client_session.prepareEnrollSession(&sup, &fake_hat, &nonce).is_err());
        // Verify the challange is invalidated.
        assert_eq!(service.revoke_challenge(&sup, challenge).unwrap(), 0);
    }

    #[test]
    fn test_prepare_enrollment_allow_hat_reuse() {
        let (_, service, auth_token_key, client_session, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        // Repeatedly prepare and cancel enrollments with the valid |hat|.
        for _ in 0..2 {
            let nonce = rng::generate_random_buffer::<32>();
            let _ = client_session.prepareEnrollSession(&sup, &hat, &nonce).unwrap();
            let enrollment_result = EnrollmentResult { enrolled: false };
            let nonce = rng::generate_random_buffer::<32>();
            let _ = client_session.finishEnrollSession(&sup, &enrollment_result, &nonce).unwrap();
        }
    }

    #[test]
    fn test_finish_enrollment() {
        // Setup: prepare_enroll_session should succeed.
        let (_, service, auth_token_key, client_session, sk) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let _ = client_session.prepareEnrollSession(&sup, &hat, &nonce).unwrap();

        // Test: finish_enroll_session should succeed.
        let nonce = rng::generate_random_buffer::<32>();
        let enrollment_result = EnrollmentResult { enrolled: true };
        let finish_resp =
            client_session.finishEnrollSession(&sup, &enrollment_result, &nonce).unwrap();

        // Verify: check response hmac should match the computation.
        let hmac = crypto::compute_hmac!(
            &sk,
            &TestBlob(&nonce),
            &TestBlob(&sup.userId.to_le_bytes()),
            &TestBlob(b"finger_guardenroll_finish")
        )
        .unwrap();
        assert!(hmac == finish_resp.mac.as_slice());
        // Ensure the authenticator id updates after enrollment.
        let new_auth_id = service.read_authenticator_id(&sup).unwrap();
        assert_ne!(i64::from(new_auth_id), 0);
    }

    #[test]
    fn test_prepare_authentication() {
        // Setup: complete an enroll session: prepare then finish.
        let (_, service, auth_token_key, client_session, sk) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let _ = client_session.prepareEnrollSession(&sup, &hat, &nonce).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let enrollment_result = EnrollmentResult { enrolled: true };
        let _ = client_session.finishEnrollSession(&sup, &enrollment_result, &nonce).unwrap();

        // Test: prepare_auth_session should succeed.
        let challenge = 0xc4a11e49e_i64;
        let nonce = rng::generate_random_buffer::<32>();
        let prepare_resp = client_session.prepareAuthSession(&sup, challenge, &nonce).unwrap();

        // Verify: check that response hmac should match the computation.
        let hmac = crypto::compute_hmac!(
            &sk,
            &TestBlob(&nonce),
            &TestBlob(&sup.userId.to_le_bytes()),
            &TestBlob(b"finger_guardauth")
        )
        .unwrap();
        assert!(hmac == prepare_resp.mac.as_slice());
    }

    #[test]
    fn test_finish_authentication() {
        // Setup: prepare and finish an enroll session then prepare an auth session.
        let (_, service, auth_token_key, client_session, sk) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let secure_user_id = 0x1337BEEF_i64;
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(secure_user_id),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let _ = client_session.prepareEnrollSession(&sup, &hat, &nonce).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let enrollment_result = EnrollmentResult { enrolled: true };
        let _ = client_session.finishEnrollSession(&sup, &enrollment_result, &nonce).unwrap();
        let auth_id = service.read_authenticator_id(&sup).unwrap();
        let challenge = 0xc4a11e49e_i64;
        let nonce = rng::generate_random_buffer::<32>();
        let prepare_resp = client_session.prepareAuthSession(&sup, challenge, &nonce).unwrap();

        // Test: finish_auth_session with a good auth result should succeed.
        let hmac = crypto::compute_hmac!(
            &sk,
            &TestBlob(&prepare_resp.nonce),
            &TestBlob(&sup.userId.to_le_bytes()),
            &TestBlob(b"fpmcuauth")
        )
        .unwrap();
        let auth_result = AuthenticationResult::from(hmac);
        let valid_hat = client_session.finishAuthSession(&sup, &auth_result).unwrap();

        // Verify: validate the produced HAT.
        // `challenge` should be the challenge passed to prepare_auth_session().
        // `userId` should be the secure user id passed to prepare_enroll_session().
        // `authenticatorId` should match the one returned by read_authenticator_id().
        // `timestamp` should match the clock now.
        // `mac` should match the HAT's MAC computation.
        assert_eq!(valid_hat.challenge, challenge);
        assert_eq!(valid_hat.userId, secure_user_id);
        assert_eq!(valid_hat.authenticatorId, auth_id.into());
        assert_eq!(valid_hat.timestamp, 0);
        assert!(
            crypto::compute_hmac!(&auth_token_key, &valid_hat).unwrap() == valid_hat.mac.as_slice()
        );
    }

    #[test]
    fn test_prepare_auth_session_timeout() {
        // Setup: prepare and finish an enroll session, then advance the clock by the default
        // timeout window.
        let (simulated_clock, service, auth_token_key, client_session, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let _ = client_session.prepareEnrollSession(&sup, &hat, &nonce).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let enrollment_result = EnrollmentResult { enrolled: true };
        let _ = client_session.finishEnrollSession(&sup, &enrollment_result, &nonce).unwrap();
        simulated_clock.advance_time(lockout::DEFAULT_AUTH_TIMEOUT_WINDOW);

        // Test: prepare_auth_session should fail.
        let challenge = 0xc4a11e49e_i64;
        let nonce = rng::generate_random_buffer::<32>();
        assert!(client_session.prepareAuthSession(&sup, challenge, &nonce).is_err());
    }

    #[test]
    fn test_prepare_auth_session_lockout() {
        // Setup: prepare and finish an enroll session, then fail 5 auth attempts in a raw.
        let (_, service, auth_token_key, client_session, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let _ = client_session.prepareEnrollSession(&sup, &hat, &nonce).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let enrollment_result = EnrollmentResult { enrolled: true };
        let _ = client_session.finishEnrollSession(&sup, &enrollment_result, &nonce).unwrap();
        let challenge = 0xc4a11e49e_i64;
        for _ in 0..5 {
            let _ = client_session
                .prepareAuthSession(&sup, challenge, &rng::generate_random_buffer::<32>())
                .unwrap();
            let _ = client_session
                .finishAuthSession(
                    &sup,
                    &AuthenticationResult { authenticated: false, mac: [0; 32] },
                )
                .unwrap();
        }

        // Test: prepare_auth_session should fail.
        assert!(client_session
            .prepareAuthSession(&sup, challenge, &rng::generate_random_buffer::<32>())
            .is_err());
    }

    #[test]
    fn test_authentication_clear_attempt_counter() {
        // Setup: prepare and finish an enroll session, then fail 4 auth attempts in a raw,
        // and finally pass one auth attempt.
        let (_, service, auth_token_key, client_session, sk) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let _ = client_session.prepareEnrollSession(&sup, &hat, &nonce).unwrap();
        let nonce = rng::generate_random_buffer::<32>();
        let enrollment_result = EnrollmentResult { enrolled: true };
        let _ = client_session.finishEnrollSession(&sup, &enrollment_result, &nonce).unwrap();
        let challenge = 0xc4a11e49e_i64;
        for _ in 0..4 {
            let _ = client_session
                .prepareAuthSession(&sup, challenge, &rng::generate_random_buffer::<32>())
                .unwrap();
            let _ = client_session
                .finishAuthSession(
                    &sup,
                    &AuthenticationResult { authenticated: false, mac: [0; 32] },
                )
                .unwrap();
        }
        let prepare_resp = client_session
            .prepareAuthSession(&sup, challenge, &rng::generate_random_buffer::<32>())
            .unwrap();
        let hmac = crypto::compute_hmac!(
            &sk,
            &TestBlob(&prepare_resp.nonce),
            &TestBlob(&sup.userId.to_le_bytes()),
            &TestBlob(b"fpmcuauth")
        )
        .unwrap();
        let auth_result = AuthenticationResult::from(hmac);
        let valid_hat = client_session.finishAuthSession(&sup, &auth_result).unwrap();
        assert!(
            crypto::compute_hmac!(&auth_token_key, &valid_hat).unwrap() == valid_hat.mac.as_slice()
        );

        // Test: another 4 failed auth attempts should be allowed.
        for _ in 0..4 {
            let _ = client_session
                .prepareAuthSession(&sup, challenge, &rng::generate_random_buffer::<32>())
                .unwrap();
            let _ = client_session
                .finishAuthSession(
                    &sup,
                    &AuthenticationResult { authenticated: false, mac: [0; 32] },
                )
                .unwrap();
        }
    }

    #[test]
    fn test_get_lockout_status_default_to_permanent_lockout() {
        let (_, service, _, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        assert!(matches!(
            service.get_lockout_status(&sup).unwrap(),
            LockoutStatus::PermanentLockout(_)
        ));
    }

    #[test]
    fn test_fingerprint_hat_reset_fails_without_rate_limiter_setup() {
        let (_, service, auth_token_key, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        assert!(service.reset_lockout(&sup, &hat).is_err());
    }

    #[test]
    fn test_reset_lockout_with_password_hat() {
        let (_, service, auth_token_key, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::PASSWORD,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        assert!(service.reset_lockout(&sup, &hat).is_ok());
        assert!(matches!(service.get_lockout_status(&sup).unwrap(), LockoutStatus::Available(_)));
    }

    #[test]
    fn test_reset_lockout_with_stale_hat() {
        let (clock, service, auth_token_key, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::PASSWORD,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        clock.advance_time(Duration::from_secs(61));
        // Reject reset because hat is more than 1 minute old
        assert!(service.reset_lockout(&sup, &hat).is_err());
    }

    #[test]
    fn test_reset_lockout_with_fingerprint_hat() {
        // Setup: reset the lockout status with a password HAT, then fail 4 auth attempts in a raw,
        // and reset the lockout status with a fingerprint HAT.
        let (_, service, auth_token_key, client_session, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::PASSWORD,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        service.reset_lockout(&sup, &hat).unwrap();
        let challenge = 0xc4a11e49e_i64;
        for _ in 0..4 {
            let _ = client_session
                .prepareAuthSession(&sup, challenge, &rng::generate_random_buffer::<32>())
                .unwrap();
            let _ = client_session
                .finishAuthSession(
                    &sup,
                    &AuthenticationResult { authenticated: false, mac: [0; 32] },
                )
                .unwrap();
        }
        let hat = UnsignedHat::new(
            challenge,
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        assert!(service.reset_lockout(&sup, &hat).is_ok());

        // Test: another 4 failed auth attempts should be allowed.
        for _ in 0..4 {
            let _ = client_session
                .prepareAuthSession(&sup, challenge, &rng::generate_random_buffer::<32>())
                .unwrap();
            let _ = client_session
                .finishAuthSession(
                    &sup,
                    &AuthenticationResult { authenticated: false, mac: [0; 32] },
                )
                .unwrap();
        }
    }

    #[test]
    fn test_reset_timeout_with_password_hat() {
        // Setup: reset the lockout status with a password HAT so a rate limiter is initialized.
        let (clock, service, auth_token_key, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::PASSWORD,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        assert!(service.reset_lockout(&sup, &hat).is_ok());
        assert!(matches!(service.get_lockout_status(&sup).unwrap(), LockoutStatus::Available(_)));
        // Advance time to timeout the rate limiter.
        clock.advance_time(lockout::DEFAULT_AUTH_TIMEOUT_WINDOW);
        assert!(matches!(
            service.get_lockout_status(&sup).unwrap(),
            LockoutStatus::PermanentLockout(_)
        ));

        // Test: reset the lockout status again, with a password HAT just created.
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::PASSWORD,
            clock.now().unwrap(),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        assert!(service.reset_lockout(&sup, &hat).is_ok());

        // Verify: the lockout status is back to available.
        assert!(matches!(service.get_lockout_status(&sup).unwrap(), LockoutStatus::Available(_)));
    }

    #[test]
    fn test_reset_timeout_with_fingerprint_hat() {
        // Setup: reset the lockout status with a password HAT so a rate limiter is initialized.
        let (clock, service, auth_token_key, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::PASSWORD,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        assert!(service.reset_lockout(&sup, &hat).is_ok());
        assert!(matches!(service.get_lockout_status(&sup).unwrap(), LockoutStatus::Available(_)));
        // Advance time to timeout the rate limiter.
        clock.advance_time(lockout::DEFAULT_AUTH_TIMEOUT_WINDOW);
        assert!(matches!(
            service.get_lockout_status(&sup).unwrap(),
            LockoutStatus::PermanentLockout(_)
        ));

        // Test: reset the lockout status again, with a fingerprint HAT just created.
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            clock.now().unwrap(),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        assert!(service.reset_lockout(&sup, &hat).is_ok());

        // Verify: the lockout status remains permanently locked out.
        assert!(matches!(
            service.get_lockout_status(&sup).unwrap(),
            LockoutStatus::PermanentLockout(_)
        ));
    }

    #[test]
    fn test_reset_timeout_rejects_invalid_hat() {
        let (_, service, _, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::PASSWORD,
            Instant::from_nanos(0),
        );
        let fake_key = crypto::Key::read_from_bytes(&[0; 32]).unwrap();
        let fake_hat = hat.sign(&fake_key).unwrap();
        assert!(service.reset_lockout(&sup, &fake_hat).is_err());
    }

    #[test]
    fn test_reset_timeout_allows_valid_hat_reuse() {
        // Setup: reset the lockout status with a password HAT so a rate limiter is initialized.
        let (_, service, auth_token_key, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::PASSWORD,
            Instant::from_nanos(0),
        );
        let hat = hat.sign(&auth_token_key).unwrap();
        assert!(service.reset_lockout(&sup, &hat).is_ok());
        assert!(matches!(service.get_lockout_status(&sup).unwrap(), LockoutStatus::Available(_)));

        // Test: expect ok to reset again with the same HAT.
        assert!(service.reset_lockout(&sup, &hat).is_ok());
    }

    #[test]
    fn test_reset_timeout_rejects_invalid_hat_challenge_reuse() {
        let (_, service, auth_token_key, _, _) = service_setup();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let hat = UnsignedHat::new(
            service.generate_challenge(&sup).unwrap(),
            SecureUserId::from(0x1337BEEF_i64),
            AuthenticatorId::generate_random(),
            AuthenticatorType::PASSWORD,
            Instant::from_nanos(0),
        );
        let fake_key = crypto::Key::read_from_bytes(&[0; 32]).unwrap();
        let fake_hat = hat.sign(&fake_key).unwrap();
        assert!(service.reset_lockout(&sup, &fake_hat).is_err());

        let hat = hat.sign(&auth_token_key).unwrap();
        assert!(service.reset_lockout(&sup, &hat).is_err());
    }

    #[test]
    fn test_sdcp_service_setup() {
        let _ = service_sdcp_session_setup();
    }

    #[test]
    fn test_sdcp_session_creation() {
        let (_, service, _, sdcp_client_state) = service_sdcp_session_setup();
        let (sdcp_claim, _) = sdcp_client_state.generate_sdcp_claim();
        assert!(service.create_sdcp_client_session(&sdcp_claim).is_ok());
    }

    #[test]
    fn test_sdcp_session_fail_with_bad_model_key_sig() {
        let (_, service, _, sdcp_client_state) = service_sdcp_session_setup();
        let (mut sdcp_claim, _) = sdcp_client_state.generate_sdcp_claim();
        sdcp_claim.modelKeySignature[0] ^= 0xFF;
        assert!(service.create_sdcp_client_session(&sdcp_claim).is_err());
    }

    #[test]
    fn test_sdcp_session_fail_with_bad_device_key_sig() {
        let (_, service, _, sdcp_client_state) = service_sdcp_session_setup();
        let (mut sdcp_claim, _) = sdcp_client_state.generate_sdcp_claim();
        sdcp_claim.deviceKeySignature[0] ^= 0xFF;
        assert!(service.create_sdcp_client_session(&sdcp_claim).is_err());
    }

    #[test]
    fn test_sdcp_session_fail_with_bad_firmware_sig() {
        let (_, service, _, sdcp_client_state) = service_sdcp_session_setup();
        let (mut sdcp_claim, _) = sdcp_client_state.generate_sdcp_claim();
        sdcp_claim.firmwareSignature[0] ^= 0xFF;
        assert!(service.create_sdcp_client_session(&sdcp_claim).is_err());
    }

    #[test]
    fn test_sdcp_session_stickiness() {
        let (_, service, _, _) = service_sdcp_session_setup();
        // Try going through non-SDCP session creation.
        let device_private_key = crypto::ec_keygen().unwrap();
        let device_public_key = crypto::ec_public_key_serialization(&device_private_key).unwrap();
        // let device_public_key_bytes: [u8; 65] = device_public_key.into();
        let _ = service.init_handshake(device_public_key).unwrap();
        let client_nonce_bytes = rng::generate_random_buffer::<32>();
        assert!(service.create_client_session((&client_nonce_bytes).into()).is_err());
    }

    #[test]
    fn test_non_sdcp_session_stickiness() {
        let (_, service, _, _, _) = service_setup();
        // Try going through SDCP session creation while a non-SDCP session has been created.
        let sdcp_client_state = SdcpClientState::new();
        let (sdcp_claim, _) = sdcp_client_state.generate_sdcp_claim();
        assert!(service.create_sdcp_client_session(&sdcp_claim).is_err());
    }

    #[test]
    fn test_sdcp_session_device_key_pinning() {
        let (_, service, _, _) = service_sdcp_session_setup();
        // Create a new sdcp client with different model key and device key.
        // Its SDCP claims will be rejected due to device key pinning.
        let sdcp_client_state = SdcpClientState::new();
        let (sdcp_claim, _) = sdcp_client_state.generate_sdcp_claim();
        assert!(service.create_sdcp_client_session(&sdcp_claim).is_err());
    }
}
