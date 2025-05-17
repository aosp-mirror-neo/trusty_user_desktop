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
use crate::storage::{AuthenticatorId, PersistedState, SensorStateIndex, SingleFileState};
use binder::Interface;
use fingerguard_api::aidl::{
    EnrollmentResult::EnrollmentResult, HandshakeResponse::HandshakeResponse,
    HardwareAuthToken::HardwareAuthToken, IFingerGuard::IFingerGuard,
    PrepareEnrollSessionResponse::PrepareEnrollSessionResponse, SessionResponse::SessionResponse,
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
use std::sync::RwLock;
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
struct InitParams {
    pk: FixedSizeEntropy,
    tpm_seed: FixedSizeEntropy,
}

impl PersistedState for InitParams {}
impl SingleFileState for InitParams {
    const FILE_NAME: &str = "fingerguard_init_params";
}

/// Implements the `IFingerGuard` AIDL interface for other Trusty apps to call.
pub struct FingerGuardService {
    init_params: RwLock<Option<InitParams>>,
    sk: RwLock<Option<FixedSizeEntropy>>,
    _auth_token_key: OnceCell<FixedSizeEntropy>,
}

impl FingerGuardService {
    pub fn new() -> Self {
        Self {
            init_params: RwLock::new(
                InitParams::load()
                    .inspect_err(|e| error!("failed to load init_params: {e:?}"))
                    .ok(),
            ),
            sk: RwLock::new(None),
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
            .write()
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
        Ok(HandshakeResponse { server_public_key: server_public_key_bytes, pk_mac: mac.to_vec() })
    }

    fn new_session(&self, client_nonce: &[u8]) -> ServiceResult<SessionResponse> {
        if client_nonce.len() != 32 {
            return Err(ServiceError::InvalidArg("client_nonce"));
        }
        let init_params = self
            .init_params
            .read()
            .map_err(|_| ServiceError::LockAcquire { name: "init_params", mode: "read" })?;
        let Some(ref init_params) = *init_params else {
            return Err(ServiceError::StateUnavailable("init_params"));
        };
        let pk = init_params.pk;
        let tpm_seed = init_params.tpm_seed;
        let mut sk =
            self.sk.write().map_err(|_| ServiceError::LockAcquire { name: "sk", mode: "write" })?;
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
        Ok(SessionResponse { nonce, wrapped_tpm_seed, iv, tag })
    }

    fn read_authenticator_id(
        &self,
        sensor_id: i32,
        user_id: i32,
    ) -> ServiceResult<AuthenticatorId> {
        let index = SensorStateIndex::new(sensor_id, user_id);
        let file_name = index.authenticator_id_file_name();
        // Treat read failure as there is no authenticator id and use the default
        // value of 0.
        let authenticator_id = AuthenticatorId::load_from(&file_name)
            .inspect_err(|e| error!("failed to read authenticator id: {e:?}"))
            .unwrap_or(AuthenticatorId::zero());
        Ok(authenticator_id)
    }

    fn generate_authenticator_id(
        &self,
        sensor_id: i32,
        user_id: i32,
    ) -> ServiceResult<AuthenticatorId> {
        let buffer = rng::generate_random_buffer::<8>();
        let authenticator_id = AuthenticatorId::read_from_bytes(&buffer)
            .map_err(|_| ServiceError::ZcConvert("failed to parse authenticator id"))?;
        let index = SensorStateIndex::new(sensor_id, user_id);
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
        _sensor_id: i32,
        _user_id: i32,
        _hat: &HardwareAuthToken,
    ) -> binder::Result<PrepareEnrollSessionResponse> {
        // TODO(401302256): implement.
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn finishEnrollSession(
        &self,
        _sensor_id: i32,
        _user_id: i32,
        _result: &EnrollmentResult,
    ) -> binder::Result<()> {
        // TODO(401302256): implement.
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn getAuthenticatorId(&self, sensor_id: i32, user_id: i32) -> binder::Result<i64> {
        FingerGuardService::read_authenticator_id(&self, sensor_id, user_id)
            .map(|id| id.as_i64())
            .inspect_err(|e| error!("getAuthenticatorId failed: {e:?}"))
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn newAuthenticatorId(&self, sensor_id: i32, user_id: i32) -> binder::Result<i64> {
        FingerGuardService::generate_authenticator_id(&self, sensor_id, user_id)
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
        let server_public_key_bytes = handshake_response.server_public_key;

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
        assert_eq!(mac, handshake_response.pk_mac);
        pk.try_into().unwrap()
    }

    #[test]
    fn new_session() {
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
        let encrypted_tpm_seed = session_response.wrapped_tpm_seed;
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

        // API newSession only allows one successful invocation per boot.
        // Calling it once more leads to an error.
        let client_nonce = vec![0u8; 32];
        assert!(service.newSession(client_nonce.as_slice()).is_err());
    }

    #[test]
    fn get_authenticator_id() {
        let service = fingerguard_api::connect_finger_guard().unwrap();
        assert_eq!(service.getAuthenticatorId(0, 0), Ok(0));
    }

    #[test]
    fn new_authenticator_id() {
        let service = fingerguard_api::connect_finger_guard().unwrap();
        let new_id = service.newAuthenticatorId(1, 1).unwrap();
        assert_ne!(new_id, 0_i64);
    }

    #[test]
    fn new_and_get_authenticator_id() {
        let service = fingerguard_api::connect_finger_guard().unwrap();
        let new_id = service.newAuthenticatorId(1, 1).unwrap();
        let got_id = service.getAuthenticatorId(1, 1).unwrap();
        assert_eq!(new_id, got_id);
    }
}
