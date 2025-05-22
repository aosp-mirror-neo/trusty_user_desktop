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

use crate::error::{ServiceError, ServiceResult};
use crate::keymint;
use crate::rng;
use crate::storage::{
    AuthenticatorId, PersistedState, SensorSessionCounter, SensorStateIndex, SingleFileState,
};
use binder::Interface;
use fingerguard_api::aidl::{
    AuthenticationResult::AuthenticationResult, EnrollmentResult::EnrollmentResult,
    HandshakeResponse::HandshakeResponse, HardwareAuthToken::HardwareAuthToken,
    IFingerGuard::IFingerGuard, PrepareAuthSessionResponse::PrepareAuthSessionResponse,
    PrepareEnrollSessionResponse::PrepareEnrollSessionResponse, SensorUserPair::SensorUserPair,
    SessionResponse::SessionResponse,
};
use log::error;
use once_cell::sync::OnceCell;
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hmac::HmacCtx;
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::symm::{encrypt_aead, Cipher};
use std::default::Default;
use std::sync::Mutex;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const NIST_P256_CURVE_NAME: Nid = Nid::X9_62_PRIME256V1;

fn ec_keygen() -> Result<EcKey<Private>, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
    let server_private_key = EcKey::generate(&group)?;
    Ok(server_private_key)
}

fn ec_public_key_serialization(
    private_key: &EcKey<Private>,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
    let mut ctx = BigNumContext::new()?;
    let server_public_key_bytes =
        private_key.public_key().to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?;
    Ok(server_public_key_bytes.to_vec())
}

fn perform_ecdh(
    server_private_key: &PKey<Private>,
    client_public_key_bytes: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
    let mut ctx = BigNumContext::new()?;
    let client_public_point = EcPoint::from_bytes(&group, &client_public_key_bytes, &mut ctx)?;
    let client_public_key: PKey<Public> =
        EcKey::from_public_key(&group, &client_public_point)?.try_into()?;
    let mut pk_deriver = Deriver::new(&server_private_key)?;
    pk_deriver.set_peer(&client_public_key)?;
    let pk = pk_deriver.derive_to_vec()?;
    Ok(pk)
}

fn compute_hmac_sha256(
    key: &FixedSizeEntropy,
    buffer: &Vec<u8>,
) -> Result<FixedSizeEntropy, openssl::error::ErrorStack> {
    let mut hmac_ctx = HmacCtx::new(key.as_slice(), Md::sha256())?;
    hmac_ctx.update(buffer.as_slice())?;
    let mut mac = [0u8; ENTROPY_SIZE];
    let _ = hmac_ctx.finalize(mac.as_mut_slice())?;
    Ok(mac)
}

const ENTROPY_SIZE: usize = 32;
type FixedSizeEntropy = [u8; ENTROPY_SIZE];

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
/// Represents the required parameters after the service initializes
/// through the init handshake.
struct InitParams {
    pk: FixedSizeEntropy,
    tpm_seed: FixedSizeEntropy,
}

impl PersistedState for InitParams {}
impl SingleFileState for InitParams {
    const FILE_NAME: &str = "fingerguard_init_params";
}

#[derive(Default, Eq, PartialEq)]
/// Represents the global state of the ongoing sensor session.
enum SensorSession {
    #[default]
    NONE,
    ENROLL {
        nonce: FixedSizeEntropy,
    },
}

/// Implements the `IFingerGuard` AIDL interface for other Trusty apps to call.
pub struct FingerGuardService {
    init_params: Mutex<Option<InitParams>>,
    sk: Mutex<Option<FixedSizeEntropy>>,
    sensor_session: Mutex<SensorSession>,
    _auth_token_key: OnceCell<FixedSizeEntropy>,
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
            _auth_token_key: OnceCell::new(),
        }
    }

    #[allow(dead_code)] // Remove once this is used.
    fn get_auth_token_key(&self) -> ServiceResult<&FixedSizeEntropy> {
        self._auth_token_key.get_or_try_init(|| keymint::get_auth_token_key())
    }

    fn init_handshake(&self, client_public_key_bytes: &[u8]) -> ServiceResult<HandshakeResponse> {
        let mut init_params = self
            .init_params
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "init_params", mode: "write" })?;
        if let Some(_) = *init_params {
            return Err(ServiceError::StateAlreadyExists("init_params"));
        }
        let server_private_key =
            ec_keygen().map_err(|e| ServiceError::OpenSsl("failed to ec keygen", e))?;
        let server_public_key_bytes = ec_public_key_serialization(&server_private_key)
            .map_err(|e| ServiceError::OpenSsl("failed to serialize server public key", e))?;
        let server_private_key: PKey<Private> = server_private_key
            .try_into()
            .map_err(|e| ServiceError::OpenSsl("failed to convert ec key to pkey", e))?;
        let pk = perform_ecdh(&server_private_key, client_public_key_bytes)
            .map_err(|e| ServiceError::OpenSsl("failed to derive pk", e))?;
        let pk: FixedSizeEntropy = {
            let len = pk.len();
            pk.try_into().map_err(|_| ServiceError::BufferSizeMismatch {
                name: "pk",
                expected: ENTROPY_SIZE,
                actual: len,
            })
        }?;
        // generate random tpm_seed.
        let tpm_seed = rng::generate_random_buffer::<ENTROPY_SIZE>();
        let mac = compute_hmac_sha256(&pk, &b"tofu".to_vec())
            .map_err(|e| ServiceError::OpenSsl("failed to compute mac", e))?;
        // save pk and tpm_seed to storage.
        let new_init_params = InitParams { pk, tpm_seed };
        new_init_params.save()?;
        *init_params = Some(new_init_params);
        Ok(HandshakeResponse { serverPublicKey: server_public_key_bytes, pkMac: mac.to_vec() })
    }

    fn new_session(&self, client_nonce: &[u8]) -> ServiceResult<SessionResponse> {
        if client_nonce.len() != 32 {
            return Err(ServiceError::InvalidArg("client_nonce"));
        }
        let init_params = self
            .init_params
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "init_params", mode: "read" })?;
        let Some(ref init_params) = *init_params else {
            return Err(ServiceError::StateUnavailable("init_params"));
        };
        let pk = init_params.pk;
        let tpm_seed = init_params.tpm_seed;
        let mut sk = self
            .sk
            .try_lock()
            .map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "write" })?;
        if let Some(_) = *sk {
            return Err(ServiceError::StateAlreadyExists("sk"));
        }
        let nonce = rng::generate_random_vec::<32>();
        let mut all_nonces = vec![0u8; 64];
        all_nonces[0..32].copy_from_slice(client_nonce);
        all_nonces[32..64].copy_from_slice(nonce.as_slice());
        let new_sk = compute_hmac_sha256(&pk, &all_nonces)
            .map_err(|e| ServiceError::OpenSsl("failed to compute sk", e))?;
        *sk = Some(new_sk);
        let cipher = Cipher::aes_256_gcm();
        let iv = rng::generate_random_vec::<12>();
        let mut tag = vec![0u8; 16];
        let wrapped_tpm_seed = encrypt_aead(
            cipher,
            new_sk.as_slice(),
            Some(iv.as_slice()),
            b"tpm_seed", // aad = "tpm_seed"
            tpm_seed.as_slice(),
            tag.as_mut_slice(),
        )
        .map_err(|e| ServiceError::OpenSsl("failed to encrypt tpm_seed", e))?;
        Ok(SessionResponse { nonce, wrappedTpmSeed: wrapped_tpm_seed, iv, tag })
    }

    // TODO(b/401302256): Verify |hat| before start the session.
    // TODO(b/401303592): Clear sensor lockout with the HAT verification.
    fn prepare_enroll_session(
        &self,
        sensor_user_pair: &SensorUserPair,
        _hat: &HardwareAuthToken,
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
        if *sensor_session != SensorSession::NONE {
            return Err(ServiceError::StateAlreadyExists("ongoing sensor session"));
        }

        // Start a new session.
        let stored_counter = SensorSessionCounter::load().unwrap_or_default();
        let session_counter = stored_counter.increment();
        session_counter.save()?;

        let nonce = rng::generate_random_buffer::<32>();
        *sensor_session = SensorSession::ENROLL { nonce };

        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        /*
         * Compute mac as HMAC_SHA256(sk, msg) where
         * msg = nonce || user_id || "fingerguard" || "enroll" || session_counter
         */
        let mut hmac_ctx = HmacCtx::new(sk.as_slice(), Md::sha256())
            .map_err(|e| ServiceError::OpenSsl("failed to init mac", e))?;
        hmac_ctx.update(&nonce).map_err(|e| ServiceError::OpenSsl("failed to mac update", e))?;
        hmac_ctx
            .update(&sensor_state_index.user_id_be_bytes())
            .map_err(|e| ServiceError::OpenSsl("failed to mac update", e))?;
        hmac_ctx
            .update(b"fingerguard")
            .map_err(|e| ServiceError::OpenSsl("failed to mac update", e))?;
        hmac_ctx.update(b"enroll").map_err(|e| ServiceError::OpenSsl("failed to mac update", e))?;
        hmac_ctx
            .update(&session_counter.as_i64().to_be_bytes())
            .map_err(|e| ServiceError::OpenSsl("failed to mac update", e))?;
        let mut mac = [0u8; ENTROPY_SIZE];
        let _ = hmac_ctx
            .finalize(mac.as_mut_slice())
            .map_err(|e| ServiceError::OpenSsl("failed to finalize mac", e))?;
        Ok(PrepareEnrollSessionResponse {
            sessionCounter: session_counter.as_i64(),
            nonce,
            mac: mac.to_vec(),
        })
    }

    fn finish_enroll_session(
        &self,
        sensor_user_pair: &SensorUserPair,
        result: &EnrollmentResult,
    ) -> ServiceResult<()> {
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
        let SensorSession::ENROLL { nonce } = *sensor_session else {
            return Err(ServiceError::StateUnavailable("ongoing enroll session"));
        };
        let sensor_state_index = SensorStateIndex::from(sensor_user_pair);
        let session_counter = SensorSessionCounter::load().unwrap_or_default();
        // Close the session.
        *sensor_session = SensorSession::NONE;
        // If enrollment succeeds, compute and compare the mac.
        if result.enrolled {
            // Compute mac as HMAC_SHA256(sk, msg) where
            // msg = nonce || user_id || "fpmcu" | "enroll" || session_counter
            let mut hmac_ctx = HmacCtx::new(sk.as_slice(), Md::sha256())
                .map_err(|e| ServiceError::OpenSsl("failed to init mac", e))?;
            hmac_ctx
                .update(&nonce)
                .map_err(|e| ServiceError::OpenSsl("failed to mac update", e))?;
            hmac_ctx
                .update(&sensor_state_index.user_id_be_bytes())
                .map_err(|e| ServiceError::OpenSsl("failed to mac update", e))?;
            hmac_ctx
                .update(b"fpmcu")
                .map_err(|e| ServiceError::OpenSsl("failed to mac update", e))?;
            hmac_ctx
                .update(b"enroll")
                .map_err(|e| ServiceError::OpenSsl("failed to mac update", e))?;
            hmac_ctx
                .update(&session_counter.as_i64().to_be_bytes())
                .map_err(|e| ServiceError::OpenSsl("failed to mac update", e))?;
            let mut mac = [0u8; ENTROPY_SIZE];
            let _ = hmac_ctx
                .finalize(mac.as_mut_slice())
                .map_err(|e| ServiceError::OpenSsl("failed to finalize mac", e))?;
            // Note that we don't use the constant time comparison for mac check.
            // because
            // 1. The attacker can't retry the mac: the session has closed regardless
            //    the verification result. So the attack surface is non-existent.
            // 2. It is complex to convince the Rust compiler not to optimize
            //    the plain for loop over two slices.
            if mac != result.mac.as_slice() {
                return Err(ServiceError::BadMac("enrollment result"));
            }
            // Generate and save a new AuthenticatorId.
            let buffer = rng::generate_random_buffer::<8>();
            let authenticator_id = AuthenticatorId::read_from_bytes(&buffer)
                .map_err(|_| ServiceError::ZcConvert("failed to parse authenticator id"))?;
            let file_name = sensor_state_index.authenticator_id_file_name();
            authenticator_id.save_to(&file_name)?;
        }
        Ok(())
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
        let buffer = rng::generate_random_buffer::<8>();
        let authenticator_id = AuthenticatorId::read_from_bytes(&buffer)
            .map_err(|_| ServiceError::ZcConvert("failed to parse authenticator id"))?;
        let index = SensorStateIndex::from(sensor_user_pair);
        let file_name = index.authenticator_id_file_name();
        authenticator_id.save_to(&file_name)?;
        Ok(authenticator_id)
    }
}

impl Interface for FingerGuardService {}

impl IFingerGuard for FingerGuardService {
    fn initHandshake(&self, client_public_key: &[u8]) -> binder::Result<HandshakeResponse> {
        FingerGuardService::init_handshake(&self, client_public_key)
            .inspect_err(|e| error!("initHandshake failed: {e:?}"))
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn newSession(&self, client_nonce: &[u8]) -> binder::Result<SessionResponse> {
        FingerGuardService::new_session(&self, client_nonce)
            .inspect_err(|e| error!("newSession failed: {e:?}"))
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn prepareEnrollSession(
        &self,
        sensor_user_pair: &SensorUserPair,
        hat: &HardwareAuthToken,
    ) -> binder::Result<PrepareEnrollSessionResponse> {
        FingerGuardService::prepare_enroll_session(&self, sensor_user_pair, hat)
            .inspect_err(|e| error!("prepareEnrollSession failed: {e:?}"))
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn finishEnrollSession(
        &self,
        sensor_user_pair: &SensorUserPair,
        result: &EnrollmentResult,
    ) -> binder::Result<()> {
        FingerGuardService::finish_enroll_session(&self, sensor_user_pair, result)
            .inspect_err(|e| error!("finishEnrollSession failed: {e:?}"))
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
    // TODO(b/401303587): implement.
    fn prepareAuthSession(
        &self,
        _sensor_user_pair: &SensorUserPair,
    ) -> binder::Result<PrepareAuthSessionResponse> {
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }
    // TODO(b/401303587): implement.
    fn finishAuthSession(
        &self,
        _sensor_user_pair: &SensorUserPair,
        _result: &AuthenticationResult,
        _tbs_hat: &HardwareAuthToken,
    ) -> binder::Result<HardwareAuthToken> {
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn getAuthenticatorId(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
        FingerGuardService::read_authenticator_id(&self, sensor_user_pair)
            .map(|id| id.as_i64())
            .inspect_err(|e| error!("getAuthenticatorId failed: {e:?}"))
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn newAuthenticatorId(&self, sensor_user_pair: &SensorUserPair) -> binder::Result<i64> {
        FingerGuardService::generate_authenticator_id(&self, sensor_user_pair)
            .map(|id| id.as_i64())
            .inspect_err(|e| error!("newAuthenticatorId failed: {e:?}"))
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::rng;
    use crate::service::compute_hmac_sha256;
    use crate::service::FixedSizeEntropy;
    use crate::service::NIST_P256_CURVE_NAME;
    use fingerguard_api::aidl::{
        EnrollmentResult::EnrollmentResult, HardwareAuthToken::HardwareAuthToken,
        SensorUserPair::SensorUserPair,
    };
    use openssl::bn::BigNumContext;
    use openssl::derive::Deriver;
    use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
    use openssl::hmac::HmacCtx;
    use openssl::md::Md;
    use openssl::pkey::{PKey, Private, Public};
    use openssl::symm::{decrypt_aead, Cipher};
    test::init!();

    #[test]
    fn connect_server() {
        let _ = fingerguard_api::connect_finger_guard().unwrap();
    }

    // Establish a shared PK with the fingerguard server.
    fn init_service() -> FixedSizeEntropy {
        // Prepare the client key pair.
        let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let client_private_key: EcKey<Private> = EcKey::generate(&group).unwrap();
        let client_public_key_bytes = client_private_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();

        // ECDH with the server.
        let service = fingerguard_api::connect_finger_guard().unwrap();
        let handshake_response = service.initHandshake(client_public_key_bytes.as_slice()).unwrap();
        let server_public_key_bytes = handshake_response.serverPublicKey;

        // Derive PK from the client side.
        let server_public_point =
            EcPoint::from_bytes(&group, &server_public_key_bytes, &mut ctx).unwrap();
        let server_public_key: PKey<Public> =
            EcKey::from_public_key(&group, &server_public_point).unwrap().try_into().unwrap();
        let client_private_key: PKey<Private> = client_private_key.try_into().unwrap();
        let mut pk_deriver = Deriver::new(&client_private_key).unwrap();
        pk_deriver.set_peer(&server_public_key).unwrap();
        let pk = pk_deriver.derive_to_vec().unwrap();
        assert_eq!(pk.len(), 32);

        // Check the computed MAC matches the one in the response.
        let mut hmac_ctx = HmacCtx::new(&pk.as_slice(), Md::sha256()).unwrap();
        hmac_ctx.update(b"tofu").unwrap();
        let mut mac = vec![0u8; 32];
        let _ = hmac_ctx.finalize(mac.as_mut_slice()).unwrap();
        assert_eq!(mac, handshake_response.pkMac);
        pk.try_into().unwrap()
    }

    #[test]
    fn everything_with_a_shared_session() {
        let pk = init_service();
        let client_nonce = rng::generate_random_vec::<32>();

        // Start a new session with the server.
        let service = fingerguard_api::connect_finger_guard().unwrap();
        let session_response = service.newSession(client_nonce.as_slice()).unwrap();
        let server_nonce = session_response.nonce;
        let all_nonce = vec![client_nonce, server_nonce].concat();
        let sk = compute_hmac_sha256(&pk, &all_nonce).unwrap();

        // Decrypt the wrapped tpm seed.
        let iv = session_response.iv;
        let tag = session_response.tag;
        let encrypted_tpm_seed = session_response.wrappedTpmSeed;
        let cipher = Cipher::aes_256_gcm();
        let aad = b"tpm_seed";
        let tpm_seed = decrypt_aead(
            cipher,
            sk.as_slice(),
            Some(iv.as_slice()),
            aad,
            encrypted_tpm_seed.as_slice(),
            tag.as_slice(),
        )
        .unwrap();
        assert_eq!(tpm_seed.len(), 32);

        // Bad AAD leads to a decryption error.
        assert!(decrypt_aead(
            cipher,
            sk.as_slice(),
            Some(iv.as_slice()),
            b"incorrect_aad",
            encrypted_tpm_seed.as_slice(),
            tag.as_slice(),
        )
        .is_err());

        // Ensure newSession only allows one successful invocation per boot.
        let client_nonce = vec![0u8; 32];
        assert!(service.newSession(client_nonce.as_slice()).is_err());

        let sensor_id = 1_i32;
        let user_id = 1_i32;
        let sup = SensorUserPair { sensorId: sensor_id, userId: user_id };

        // ---- Start Enrollment Test ----

        // TODO(b/401302256): use a valid HAT.
        let hat = HardwareAuthToken {
            version: 0,
            challenge: 0,
            userId: 0,
            authenticatorId: 0,
            authenticatorType: 0,
            timestamp: 0,
            mac: vec![],
        };
        let session_resp = service.prepareEnrollSession(&sup, &hat).unwrap();
        let mut hmac_ctx = HmacCtx::new(sk.as_slice(), Md::sha256()).unwrap();
        hmac_ctx.update(&session_resp.nonce).unwrap();
        hmac_ctx.update(&user_id.to_be_bytes()).unwrap();
        hmac_ctx.update(b"fingerguardenroll").unwrap();
        hmac_ctx.update(&session_resp.sessionCounter.to_be_bytes()).unwrap();
        let mut mac = [0u8; 32];
        let _ = hmac_ctx.finalize(mac.as_mut_slice()).unwrap();
        assert_eq!(mac.to_vec(), session_resp.mac);

        let old_auth_id = service.getAuthenticatorId(&sup).unwrap();
        let mut hmac_ctx = HmacCtx::new(sk.as_slice(), Md::sha256()).unwrap();
        hmac_ctx.update(&session_resp.nonce).unwrap();
        hmac_ctx.update(&user_id.to_be_bytes()).unwrap();
        hmac_ctx.update(b"fpmcuenroll").unwrap();
        hmac_ctx.update(&session_resp.sessionCounter.to_be_bytes()).unwrap();
        let mut mac = [0u8; 32];
        let _ = hmac_ctx.finalize(mac.as_mut_slice()).unwrap();
        let enrollment_result = EnrollmentResult { enrolled: true, mac: mac.to_vec() };
        let _ = service.finishEnrollSession(&sup, &enrollment_result).unwrap();
        // Ensure the authenticator id updates after enrollment.
        let new_auth_id = service.getAuthenticatorId(&sup).unwrap();
        assert_ne!(new_auth_id, old_auth_id);

        // TODO(b/401302256): test enrollment cancellation.
        // ---- End Enrollment Test ----
    }

    #[test]
    fn get_authenticator_id() {
        let service = fingerguard_api::connect_finger_guard().unwrap();
        let sup = SensorUserPair { sensorId: 0, userId: 0 };
        assert_eq!(service.getAuthenticatorId(&sup), Ok(0));
    }

    #[test]
    fn new_authenticator_id() {
        let service = fingerguard_api::connect_finger_guard().unwrap();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let new_id = service.newAuthenticatorId(&sup).unwrap();
        assert_ne!(new_id, 0_i64);
    }

    #[test]
    fn new_and_get_authenticator_id() {
        let service = fingerguard_api::connect_finger_guard().unwrap();
        let sup = SensorUserPair { sensorId: 1, userId: 1 };
        let new_id = service.newAuthenticatorId(&sup).unwrap();
        let got_id = service.getAuthenticatorId(&sup).unwrap();
        assert_eq!(new_id, got_id);
    }
}
