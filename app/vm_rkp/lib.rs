/*
* Copyright (C) 2026 The Android Open Source Project
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

use avf_attestation::{
    AttestationOps, ClientVmDiceChain, InMemoryKeyDerivationOps, KeyDerivationOps,
    RequestProcessingError,
};
use ciborium::Value;
use coset::{CborSerializable, CoseSign1};
use hwbcc::{get_bcc, sign_data, HwBccMode, SigningAlgorithm, HWBCC_MAX_RESP_PAYLOAD_LENGTH};
use hwkey::{Hwkey, KdfVersion, OsRollbackVersion, RollbackVersionSource};
use keymint_legacy_client::KeyMintSecureLegacyClient;
use log::error;
use rkp_ta::main_event_loop;
use tipc::TipcError;
use trusty_sys::Error;
use zeroize::Zeroizing;

const VM_RKP_SERVICE_PORT: &str = "android.trusty.vm_attestation.IVmAttestation/default";

const VM_RKP_KEK_SIZE: usize = 32;
const VM_RKP_KEK_CONTEXT: &[u8] = b"VmRkp\0";

// Suffix after pvmfw includes Trusty TEE VM and VM RKP app.
const DICE_CHAIN_SUFFIX_LEN: usize = 2;

// Key for the UDS certificates in the CBOR map.
const UDS_CERTS_KEY: &str = "ChromeOS PCA v1";

struct Ops {
    bcc: Vec<u8>,
    key_derivation_ops: InMemoryKeyDerivationOps,
}

impl Ops {
    fn new(bcc: Vec<u8>, secret: Zeroizing<[u8; 32]>) -> avf_attestation::Result<Self> {
        let ops = Self { bcc, key_derivation_ops: Zeroizing::new(secret.to_vec()).into() };
        Ok(ops)
    }
}

impl KeyDerivationOps for Ops {
    fn derive_kek(&self, salt: &[u8], info: &[u8]) -> avf_attestation::Result<Zeroizing<[u8; 32]>> {
        let kek = self.key_derivation_ops.derive_kek(salt, info)?;
        Ok(kek)
    }
}

impl AttestationOps for Ops {
    fn reference_vm_dice_chain(&self) -> avf_attestation::Result<&[u8]> {
        Ok(&self.bcc)
    }

    fn reference_vm_dice_chain_suffix_len(&self) -> usize {
        DICE_CHAIN_SUFFIX_LEN
    }

    fn sign_with_cdi_leaf(&self, payload: &[u8]) -> avf_attestation::Result<CoseSign1> {
        let mut cose_sign1_buf = [0u8; HWBCC_MAX_RESP_PAYLOAD_LENGTH];
        // Note: Test mode is ignored as this currently supports only IRPC V3.
        let cose_sign1_bytes = sign_data(
            HwBccMode::Release,
            SigningAlgorithm::ED25519,
            payload,
            &[],
            &mut cose_sign1_buf,
        )
        .map_err(|e| {
            error!("failed to get signed data: {:?}", e);
            RequestProcessingError::InternalError
        })?;
        let value = CoseSign1::from_slice(cose_sign1_bytes).map_err(|e| {
            error!("failed to deserialize signed data: {:?}", e);
            RequestProcessingError::InternalError
        })?;
        Ok(value)
    }

    fn validate_vm(&self, _client_chain_suffix: &ClientVmDiceChain) -> avf_attestation::Result<()> {
        Ok(())
    }

    fn uds_certs(&self) -> avf_attestation::Result<Vec<u8>> {
        get_uds_certificates()
    }
}

/// Helper function to serialize a `cbor::value::Value` into bytes.
fn serialize_cbor(cbor_value: &Value) -> avf_attestation::Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(cbor_value, &mut buf)
        .map_err(|_| RequestProcessingError::InternalError)?;
    Ok(buf)
}

// Function to get UDS certificates from KeyMint and encode them in a CBOR map.
fn get_uds_certificates() -> avf_attestation::Result<Vec<u8>> {
    let mut km = match KeyMintSecureLegacyClient::new() {
        Ok(km_client) => km_client,
        Err(e) => {
            error!("failed to create KeyMint legacy client: {:?}", e);
            return serialize_cbor(&Value::Map(Vec::new()));
        }
    };

    match km.get_uds_certs() {
        Ok(certs_vec) => {
            if certs_vec.is_empty() {
                error!("no UDS certificates found");
                return serialize_cbor(&Value::Map(Vec::new()));
            }
            let encoded_certs = certs_vec.into_iter().map(Value::Bytes).collect::<Vec<_>>();
            let uds_certs_cbor = Value::Map(vec![(
                Value::Text(UDS_CERTS_KEY.to_string()),
                Value::Array(encoded_certs),
            )]);

            serialize_cbor(&uds_certs_cbor)
        }
        Err(e) => {
            error!("failed to get UDS certs: {:?}, returning empty certs", e);
            serialize_cbor(&Value::Map(Vec::new()))
        }
    }
}

pub fn init_and_start_loop() -> Result<(), TipcError> {
    trusty_log::init();

    let mut bcc_buf = [0u8; HWBCC_MAX_RESP_PAYLOAD_LENGTH];
    let bcc =
        get_bcc(HwBccMode::Release, &mut bcc_buf).map_err(|_| TipcError::SystemError(Error::IO))?;

    let hwkey_session = Hwkey::open().map_err(|_| TipcError::SystemError(Error::IO))?;
    let mut key_buffer = [0; VM_RKP_KEK_SIZE];
    let _ = hwkey_session
        .derive_key_req()
        .unique_key()
        .kdf(KdfVersion::Best)
        .os_rollback_version(OsRollbackVersion::Current)
        .rollback_version_source(RollbackVersionSource::RunningVersion)
        .derive(VM_RKP_KEK_CONTEXT, &mut key_buffer)
        .map_err(|_| TipcError::SystemError(Error::Generic))?;

    let attestation_ops =
        Ops::new(bcc.to_vec(), Zeroizing::new(key_buffer)).map_err(|_| TipcError::InvalidData)?;

    let _ = main_event_loop(attestation_ops, VM_RKP_SERVICE_PORT);
    Ok(())
}
