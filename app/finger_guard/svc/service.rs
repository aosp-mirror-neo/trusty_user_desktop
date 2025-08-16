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

use crate::clock;
use crate::keymint;
use crate::storage::{PersistedState, SingleFileState};
use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::{
    AuthenticationResult::AuthenticationResult, EnrollmentResult::EnrollmentResult,
    FinishEnrollSessionResponse::FinishEnrollSessionResponse, HandshakeResponse::HandshakeResponse,
    HardwareAuthToken::HardwareAuthToken, IFingerGuard::IFingerGuard, LockoutStatus::LockoutStatus,
    PrepareAuthSessionResponse::PrepareAuthSessionResponse,
    PrepareEnrollSessionResponse::PrepareEnrollSessionResponse, SensorUserPair::SensorUserPair,
    SessionResponse::SessionResponse,
};
use binder::Interface;
use finger_guard::aidl;
use finger_guard::crypto::{self, HmacSignable, MapOpenSslErrExt};
use finger_guard::error::{ServiceError, ServiceResult};
use finger_guard::hat::{AuthenticatorType, UnsignedHat, EMPTY_HAT};
use finger_guard::identifiers::{AuthenticatorId, SecureUserId, SensorStateIndex};
use finger_guard::rng;
use finger_guard::time::Instant;
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
struct InitParams {
    pk: crypto::Key,
    tpm_seed: crypto::Secret,
}

impl PersistedState for InitParams {}
impl SingleFileState for InitParams {
    const FILE_NAME: &str = "finger_guard_init_params";
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
pub struct FingerGuardService {
    init_params: Mutex<Option<InitParams>>,
    sk: Mutex<Option<crypto::Key>>,
    sensor_session: Mutex<SensorSession>,
    auth_token_key: OnceCell<crypto::Key>,
    enrollment_challenges: Mutex<BTreeMap<EnrollmentChallenge, Instant>>,
}

/// The initial message signed by the private key during the handshake.
struct HandshakeMessage;
impl HmacSignable for HandshakeMessage {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        add_bytes(b"tofu")
    }
}

impl FingerGuardService {
    pub fn new() -> Self {
        Self {
            init_params: Mutex::new(
                InitParams::load()
                    .inspect_err(|e| error!("failed to load init_params: {e:?}"))
                    .ok(),
            ),
            sk: Mutex::new(None),
            sensor_session: Mutex::new(SensorSession::default()),
            auth_token_key: OnceCell::new(),
            enrollment_challenges: Mutex::new(BTreeMap::new()),
        }
    }

    fn get_auth_token_key(&self) -> ServiceResult<&crypto::Key> {
        self.auth_token_key.get_or_try_init(|| keymint::get_auth_token_key())
    }

    fn init_handshake(&self, client_public_key_bytes: &[u8]) -> ServiceResult<HandshakeResponse> {
        let mut init_params = self
            .init_params
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "init_params", mode: "write" })?;
        if let Some(_) = *init_params {
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
        new_init_params.save()?;
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
        if let Some(_) = *sk {
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
        let valid_until = clock::now()? + Duration::from_secs(60);
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
        let now = clock::now()?;
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
        let challenge =
            FingerGuardService::revoke_challenge(&self, sensor_user_pair, hat.challenge)?;
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
        secure_user_id.save_to(&sid_file)?;
        // Start a new enroll session.
        let nonce = crypto::Nonce::import(nonce)?;
        let hmac = crypto::sensor_session_message_hmac(
            &sk,
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
                &sk,
                &nonce,
                crypto::MessageSender::FingerGuard,
                crypto::SensorSessionType::EnrollFinish,
                &sensor_state_index,
            )?;
            // Generate and save a new AuthenticatorId.
            let authenticator_id = AuthenticatorId::generate_random();
            let file_name = sensor_state_index.authenticator_id_file_name();
            authenticator_id.save_to(&file_name)?;
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
            &sk,
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
                &sk,
                &nonce,
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
            let authenticator_id = AuthenticatorId::load_from(&aid_file_name)?;
            let secure_user_id = SecureUserId::load_from(&sid_file_name)?;
            let hat = UnsignedHat::new(
                challenge,
                secure_user_id,
                authenticator_id,
                AuthenticatorType::FINGERPRINT,
                clock::now()?,
            );
            let hat = hat.sign(&auth_token_key)?;
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
        let authenticator_id = AuthenticatorId::load_from(&file_name)
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
        authenticator_id.save_to(&file_name)?;
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

impl Interface for FingerGuardService {}

impl IFingerGuard for FingerGuardService {
    fn initHandshake(&self, client_public_key: &[u8]) -> binder::Result<HandshakeResponse> {
        service_result_to_binder_result(
            "initHandshake",
            FingerGuardService::init_handshake(&self, client_public_key),
        )
    }
    fn newSession(&self, client_nonce: &[u8]) -> binder::Result<SessionResponse> {
        service_result_to_binder_result(
            "newSession",
            FingerGuardService::new_session(&self, client_nonce),
        )
    }
    fn generateChallenge(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
        service_result_to_binder_result(
            "generateChallenge",
            FingerGuardService::generate_challenge(&self, sensor_user_pair),
        )
    }
    fn revokeChallenge(
        &self,
        sensor_user_pair: &SensorUserPair,
        challenge: i64,
    ) -> binder::Result<i64> {
        service_result_to_binder_result(
            "revokeChallenge",
            FingerGuardService::revoke_challenge(&self, sensor_user_pair, challenge),
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
            FingerGuardService::prepare_enroll_session(&self, sensor_user_pair, hat, nonce),
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
            FingerGuardService::finish_enroll_session(&self, sensor_user_pair, result, nonce),
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
            FingerGuardService::prepare_auth_session(&self, sensor_user_pair, challenge, nonce),
        )
    }
    fn finishAuthSession(
        &self,
        sensor_user_pair: &SensorUserPair,
        result: &AuthenticationResult,
    ) -> binder::Result<HardwareAuthToken> {
        service_result_to_binder_result(
            "finishAuthSession",
            FingerGuardService::finish_auth_session(&self, sensor_user_pair, result),
        )
    }
    fn getAuthenticatorId(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
        service_result_to_binder_result(
            "getAuthenticatorId",
            FingerGuardService::read_authenticator_id(&self, sensor_user_pair).map(|id| id.into()),
        )
    }
    fn newAuthenticatorId(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
        service_result_to_binder_result(
            "newAuthenticatorId",
            FingerGuardService::generate_authenticator_id(&self, sensor_user_pair)
                .map(|id| id.into()),
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

#[cfg(test)]
mod tests {
    use crate::keymint;
    use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::{
        AuthenticationResult::AuthenticationResult, EnrollmentResult::EnrollmentResult,
        SensorUserPair::SensorUserPair,
    };
    use finger_guard::crypto::{self, NIST_P256_CURVE_NAME};
    use finger_guard::error::ServiceResult;
    use finger_guard::hat::{AuthenticatorType, UnsignedHat};
    use finger_guard::identifiers::{AuthenticatorId, SecureUserId};
    use finger_guard::rng;
    use finger_guard::time::Instant;
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use test::{assert, assert_eq, assert_ne, assert_ok, skip};
    use zerocopy::FromBytes;

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

    test::init!();

    #[test]
    fn connect_server() {
        let _ = assert_ok!(finger_guard_api::connect_finger_guard());
    }

    #[test]
    fn everything_with_a_shared_session() {
        let auth_token_key = assert_ok!(keymint::get_auth_token_key());

        // Prepare the client key pair.
        let group = assert_ok!(EcGroup::from_curve_name(NIST_P256_CURVE_NAME));
        let mut ctx = assert_ok!(BigNumContext::new());
        let client_private_key = assert_ok!(EcKey::generate(&group));
        let client_public_key_bytes = assert_ok!(client_private_key.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut ctx
        ));

        // ECDH with the server. If the service has already done a handshake then it's not
        // possible to run this test, skip it and move on.
        let service = assert_ok!(finger_guard_api::connect_finger_guard());
        let handshake = match service.initHandshake(client_public_key_bytes.as_slice()) {
            Err(status) if status.transaction_error() == binder::StatusCode::ALREADY_EXISTS => {
                skip!("service already bound to a controller")
            }
            result => assert_ok!(result),
        };
        let server_public_key_bytes = handshake.serverPublicKey;

        // Derive PK from the client side.
        let pk = assert_ok!(crypto::perform_ecdh(client_private_key, &server_public_key_bytes));

        // Check the computed MAC matches the one in the response.
        let hmac = assert_ok!(crypto::compute_hmac!(&pk, &TestBlob(b"tofu")));
        assert!(hmac == handshake.pkMac.as_slice());

        // Generate the client nonce.
        let client_nonce = rng::generate_random_vec::<32>();

        // Start a new session with the server.
        let service = assert_ok!(finger_guard_api::connect_finger_guard());
        let session_response = assert_ok!(service.newSession(client_nonce.as_slice()));
        let sk = assert_ok!(crypto::compute_hmac!(
            &pk,
            &TestBlob(&client_nonce),
            &TestBlob(&session_response.nonce)
        ));

        // Decrypt the wrapped tpm seed.
        let iv = assert_ok!(crypto::Iv::read_from_bytes(session_response.iv.as_slice()));
        let tag = assert_ok!(crypto::Aes256Tag::read_from_bytes(session_response.tag.as_slice()));
        let encrypted_tpm_seed = session_response.wrappedTpmSeed;
        let aad = b"tpm_seed";
        assert_ok!(crypto::decrypt_aes256_gcm(&sk, &iv, aad, encrypted_tpm_seed.as_slice(), &tag,));

        // Convert the HMAC into a key.
        let sk = crypto::Key::from(sk);

        // Ensure newSession only allows one successful invocation per boot.
        assert!(service.newSession(vec![0u8; 32].as_slice()).is_err());

        let sensor_id = 1_i32;
        let user_id = 1_i32;
        let sup = SensorUserPair { sensorId: sensor_id, userId: user_id };
        let secure_user_id_int = 0x1337BEEF_i64;
        let secure_user_id = SecureUserId::from(secure_user_id_int);

        // ---- Start Enrollment Test ----
        let hat = UnsignedHat::new(
            assert_ok!(service.generateChallenge(&sup)),
            secure_user_id,
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = assert_ok!(hat.sign(&auth_token_key));
        let nonce = rng::generate_random_vec::<32>();
        let session_resp = assert_ok!(service.prepareEnrollSession(&sup, &hat, &nonce));
        let hmac = assert_ok!(crypto::compute_hmac!(
            &sk,
            &TestBlob(&nonce),
            &TestBlob(&user_id.to_be_bytes()),
            &TestBlob(b"finger_guardenroll")
        ));
        assert!(hmac == session_resp.mac.as_slice());

        let old_auth_id = assert_ok!(service.getAuthenticatorId(&sup));
        let nonce = rng::generate_random_vec::<32>();
        let enrollment_result = EnrollmentResult { enrolled: true };
        let finish_resp = assert_ok!(service.finishEnrollSession(&sup, &enrollment_result, &nonce));
        // Ensure the authenticator id updates after enrollment.
        let new_auth_id = assert_ok!(service.getAuthenticatorId(&sup));
        assert_ne!(new_auth_id, old_auth_id);
        let hmac = assert_ok!(crypto::compute_hmac!(
            &sk,
            &TestBlob(&nonce),
            &TestBlob(&user_id.to_be_bytes()),
            &TestBlob(b"finger_guardenroll_finish")
        ));
        assert!(hmac == finish_resp.mac.as_slice());

        // Test enrollment session cancellation.
        let hat = UnsignedHat::new(
            assert_ok!(service.generateChallenge(&sup)),
            secure_user_id,
            AuthenticatorId::generate_random(),
            AuthenticatorType::FINGERPRINT,
            Instant::from_nanos(0),
        );
        let hat = assert_ok!(hat.sign(&auth_token_key));
        let nonce = rng::generate_random_vec::<32>();
        let _ = assert_ok!(service.prepareEnrollSession(&sup, &hat, &nonce));
        let cancel_result = EnrollmentResult { enrolled: false };
        let _ = assert_ok!(service.finishEnrollSession(&sup, &cancel_result, &nonce));
        // ---- End Enrollment Test ----

        // ---- Start Authentication Test ----
        let challenge = 0xc4a11e49e_i64;
        let nonce = rng::generate_random_vec::<32>();
        let session_resp = assert_ok!(service.prepareAuthSession(&sup, challenge, &nonce));
        let hmac = assert_ok!(crypto::compute_hmac!(
            &sk,
            &TestBlob(&nonce),
            &TestBlob(&user_id.to_be_bytes()),
            &TestBlob(b"finger_guardauth")
        ));
        assert!(hmac == session_resp.mac.as_slice());

        let hmac = assert_ok!(crypto::compute_hmac!(
            &sk,
            &TestBlob(&nonce),
            &TestBlob(&user_id.to_be_bytes()),
            &TestBlob(b"fpmcuauth")
        ));
        let auth_result = AuthenticationResult::from(hmac);
        let valid_hat = assert_ok!(service.finishAuthSession(&sup, &auth_result));
        assert_eq!(valid_hat.challenge, challenge);
        assert_eq!(valid_hat.userId, secure_user_id_int);
        assert_eq!(valid_hat.authenticatorId, new_auth_id);
        assert_ne!(valid_hat.timestamp, 0);
        assert!(
            crypto::compute_hmac!(&auth_token_key, &valid_hat).unwrap() == valid_hat.mac.as_slice()
        );

        // ---- End Authentication Test ----
    }

    #[test]
    fn get_authenticator_id() {
        let service = assert_ok!(finger_guard_api::connect_finger_guard());
        let sup = SensorUserPair { sensorId: 0, userId: 0 };
        assert_eq!(service.getAuthenticatorId(&sup), Ok(0));
    }

    #[test]
    fn new_authenticator_id() {
        let service = assert_ok!(finger_guard_api::connect_finger_guard());
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let new_id = assert_ok!(service.newAuthenticatorId(&sup));
        assert_ne!(new_id, 0_i64);
    }

    #[test]
    fn new_and_get_authenticator_id() {
        let service = assert_ok!(finger_guard_api::connect_finger_guard());
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let new_id = assert_ok!(service.newAuthenticatorId(&sup));
        let got_id = assert_ok!(service.getAuthenticatorId(&sup));
        assert_eq!(new_id, got_id);
    }

    #[test]
    fn generate_and_revoke_challenge() {
        let service = assert_ok!(finger_guard_api::connect_finger_guard());
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        // Generate multiple challenges and revoke them individually.
        let c1 = assert_ok!(service.generateChallenge(&sup));
        assert_ne!(c1, 0_i64);
        let c2 = assert_ok!(service.generateChallenge(&sup));
        assert_ne!(c2, 0_i64);
        assert_ne!(c1, c2);
        // Revoke once, return the same challenge.
        let revoked_c1 = assert_ok!(service.revokeChallenge(&sup, c1));
        assert_eq!(c1, revoked_c1);
        let revoked_c2 = assert_ok!(service.revokeChallenge(&sup, c2));
        assert_eq!(c2, revoked_c2);
        // Revoke the 1st challenge twice, return zero.
        assert_eq!(service.revokeChallenge(&sup, c1), Ok(0));
    }

    #[test]
    fn revoke_invalid_challenge() {
        let service = assert_ok!(finger_guard_api::connect_finger_guard());
        let sup = SensorUserPair { sensorId: 2, userId: 2 };
        let invalid_challenge = 1234_i64;
        assert_eq!(service.revokeChallenge(&sup, invalid_challenge), Ok(0));
    }
}
