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

use crate::{device, operation, rkp};
use android_system_desktop_security_gsc::aidl::android::system::desktop::security::gsc::IGsc::IGsc;
use binder::Strong;
use gsc_svc_client::GscServiceClient;
use kmr_common::{km_err, try_to_vec, Error, ErrorKind};
use kmr_ta::{HalInfo, HardwareInfo, RpcInfo};
use kmr_wire::{
    cbor,
    cbor::cbor,
    frp::ErrorCode as FrpErrorCode,
    keymint::{BootInfo, ErrorCode, KeyParam, SecurityLevel, VerifiedBootState},
    rpc::*,
    *,
};
use log::{error, info, trace, warn};
use tpm_commands::strongbox::enable_strongbox;
use tpm_commands::{TpmRequestMessage, TpmResponseMessage};
use zerocopy::{FromBytes, IntoBytes};

pub struct StrongBox {
    tpm: Strong<dyn IGsc>,
    additional_attestation_info: Option<Vec<u8>>,
    attestation_id_info: Option<AttestationIdInfo>,
    boot_info: Option<BootInfo>,
    hal_info: Option<HalInfo>,
    hw_info: HardwareInfo,
    rpc_info: RpcInfo,
    enabled: bool,
}

impl StrongBox {
    pub fn new(hw_info: HardwareInfo, rpc_info: RpcInfo) -> Result<Self, Error> {
        let tpm = GscServiceClient::default().0;

        Ok(Self {
            tpm,
            additional_attestation_info: None,
            attestation_id_info: None,
            boot_info: None,
            hal_info: None,
            hw_info,
            rpc_info,
            enabled: false,
        })
    }

    pub fn init(&mut self) {
        if self.enabled {
            return;
        }
        loop {
            // This command needs to be sent after gscd connects and before any other apps try to use
            // the GSC. This can be accomplished by looping until a successful transmit is made.
            // TODO: This may latency to overall boot due to synchronous operation
            let cmd = TpmRequestMessage::new(enable_strongbox::Request { enable: 1 });
            let rsp = self.tpm.transmit(cmd.as_bytes());
            if let Ok(rsp) = rsp {
                let rsp =
                    TpmResponseMessage::<enable_strongbox::Response>::ref_from_bytes(&rsp).unwrap();
                // 0x57F is returned if the GSC firmware hasn't added this command yet and SB is
                // enabled by default.
                if rsp.header.error_code == 0 || rsp.header.error_code == 0x57F {
                    info!("gcsd successfully enabled Strongbox {:#x}", rsp.header.error_code);
                    self.enabled = true;
                    break;
                } else {
                    error!("gscd failed to enable Strongbox. TPM_RC: {:#x}", rsp.header.error_code);
                }
            } else {
                error!("Failed to init SB. Retrying...");
            }
            // SAFETY: `clock_id` and `flags` are both zero, as required by the
            // `trusty_nanosleep` docs.
            unsafe {
                trusty_sys::nanosleep(0, 0, 50000000);
            }
        }
    }

    /// Process a single serialized request, returning a serialized response.
    pub fn process(&mut self, req_data: &[u8]) -> Vec<u8> {
        self.init();
        let (req_code, rsp) = match PerformOpReq::from_slice(req_data) {
            Ok(req) => {
                trace!("-> TA: received request {:?}", req.code());
                (Some(req.code()), self.process_req(req))
            }
            Err(e) => {
                error!("failed to decode CBOR request: {e:?}");
                // We need to report the error to the HAL, but we don't know whether the request was
                // for the `IRemotelyProvisionedComponent` or for one of the other HALs, so we don't
                // know what numbering space the error codes are expected to be in.  Assume the
                // shared KeyMint `ErrorCode` space.
                (None, error_rsp(ErrorCode::EncodingError as i32))
            }
        };
        trace!("<- TA: send response {:?} rc {}", req_code, rsp.error_code);
        match rsp.into_vec() {
            Ok(rsp_data) => rsp_data,
            Err(e) => {
                error!("failed to encode CBOR response: {e:?}");
                invalid_cbor_rsp_data().to_vec()
            }
        }
    }
    fn process_req(&mut self, req: PerformOpReq) -> PerformOpResponse {
        match req {
            PerformOpReq::DeviceAddRngEntropy(_req) => {
                // The GSC has a HWRNG so this is a no-op.
                op_ok_rsp(PerformOpRsp::DeviceAddRngEntropy(AddRngEntropyResponse {}))
            }
            PerformOpReq::DeviceBegin(req) => match device::begin(req, &self.tpm) {
                Ok(resp) => op_ok_rsp(PerformOpRsp::DeviceBegin(resp)),
                Err(err) => op_error_rsp(KeyMintOperation::DeviceBegin, err),
            },
            PerformOpReq::DeviceGenerateKey(req) => match device::generate_key(req, &self.tpm) {
                Ok(resp) => op_ok_rsp(PerformOpRsp::DeviceGenerateKey(resp)),
                Err(err) => op_error_rsp(KeyMintOperation::DeviceGenerateKey, err),
            },
            PerformOpReq::DeviceGetHardwareInfo(req) => {
                match device::get_hardware_info(req, &self.tpm) {
                    Ok(resp) => op_ok_rsp(PerformOpRsp::DeviceGetHardwareInfo(resp)),
                    Err(err) => op_error_rsp(KeyMintOperation::DeviceGetHardwareInfo, err),
                }
            }
            PerformOpReq::OperationFinish(req) => match operation::finish(req, &self.tpm) {
                Ok(resp) => op_ok_rsp(PerformOpRsp::OperationFinish(resp)),
                Err(err) => op_error_rsp(KeyMintOperation::OperationFinish, err),
            },
            PerformOpReq::OperationUpdate(req) => match operation::update(req, &self.tpm) {
                Ok(resp) => op_ok_rsp(PerformOpRsp::OperationUpdate(resp)),
                Err(err) => op_error_rsp(KeyMintOperation::OperationUpdate, err),
            },
            PerformOpReq::RpcGenerateCertificateV2Request(req) => match self.rpc_device_info_cbor()
            {
                Ok(device_info) => {
                    match rkp::generate_certificate_request_v2(req, device_info, &self.tpm) {
                        Ok(resp) => op_ok_rsp(PerformOpRsp::RpcGenerateCertificateV2Request(resp)),
                        Err(err) => {
                            op_error_rsp(KeyMintOperation::RpcGenerateCertificateV2Request, err)
                        }
                    }
                }
                Err(err) => op_error_rsp(KeyMintOperation::RpcGenerateCertificateV2Request, err),
            },
            PerformOpReq::RpcGenerateEcdsaP256KeyPair(req) => {
                match rkp::generate_ecdsa_p256_keypair(req, &self.tpm) {
                    Ok(resp) => op_ok_rsp(PerformOpRsp::RpcGenerateEcdsaP256KeyPair(resp)),
                    Err(err) => op_error_rsp(KeyMintOperation::RpcGenerateEcdsaP256KeyPair, err),
                }
            }
            PerformOpReq::RpcGetHardwareInfo(_req) => match self.get_rpc_hardware_info() {
                Ok(ret) => {
                    op_ok_rsp(PerformOpRsp::RpcGetHardwareInfo(GetRpcHardwareInfoResponse { ret }))
                }
                Err(e) => op_error_rsp(GetRpcHardwareInfoRequest::CODE, e),
            },
            PerformOpReq::SetAdditionalAttestationInfo(req) => {
                for param in req.info {
                    match param {
                        KeyParam::ModuleHash(hash) => {
                            if let Some(existing) = self.additional_attestation_info() {
                                if existing == hash {
                                    continue;
                                }
                            }
                            if !self.set_additional_attestation_info(hash) {
                                return op_error_rsp(
                                    KeyMintOperation::SetAdditionalAttestationInfo,
                                    km_err!(ModuleHashAlreadySet, ""),
                                );
                            }
                        }
                        _ => {
                            return op_error_rsp(
                                KeyMintOperation::SetAdditionalAttestationInfo,
                                km_err!(InvalidTag, "unexpected tag"),
                            )
                        }
                    }
                }
                op_ok_rsp(PerformOpRsp::SetAdditionalAttestationInfo(
                    SetAdditionalAttestationInfoResponse {},
                ))
            }
            PerformOpReq::SetAttestationIds(req) => {
                if !self.set_attestation_id_info(req.ids) {
                    op_error_rsp(
                        KeyMintOperation::SetAttestationIds,
                        km_err!(AttestationIdsNotProvisioned, "attestation IDs already set"),
                    )
                } else {
                    op_ok_rsp(PerformOpRsp::SetAttestationIds(SetAttestationIdsResponse {}))
                }
            }
            PerformOpReq::SetBootInfo(req) => {
                if !self.set_boot_info(BootInfo {
                    verified_boot_key: req.verified_boot_key,
                    device_boot_locked: req.device_boot_locked,
                    verified_boot_state: VerifiedBootState::try_from(req.verified_boot_state)
                        .unwrap_or(VerifiedBootState::Failed),
                    verified_boot_hash: req.verified_boot_hash,
                    boot_patchlevel: req.boot_patchlevel,
                }) {
                    op_error_rsp(
                        KeyMintOperation::SetBootInfo,
                        km_err!(HardwareNotYetAvailable, "boot info already set"),
                    )
                } else {
                    op_ok_rsp(PerformOpRsp::SetBootInfo(SetBootInfoResponse {}))
                }
            }
            PerformOpReq::SetHalInfo(req) => {
                if !self.set_hal_info(HalInfo {
                    os_version: req.os_version,
                    os_patchlevel: req.os_patchlevel,
                    vendor_patchlevel: req.vendor_patchlevel,
                }) {
                    op_error_rsp(
                        KeyMintOperation::SetHalInfo,
                        km_err!(HardwareNotYetAvailable, "HAL info already set"),
                    )
                } else {
                    op_ok_rsp(PerformOpRsp::SetHalInfo(SetHalInfoResponse {}))
                }
            }
            PerformOpReq::DeviceEarlyBootEnded(_req) => {
                op_ok_rsp(PerformOpRsp::DeviceEarlyBootEnded(EarlyBootEndedResponse {}))
            }
            PerformOpReq::SetHalVersion(_req) => {
                op_ok_rsp(PerformOpRsp::SetHalVersion(SetHalVersionResponse {}))
            }
            PerformOpReq::GetRootOfTrustChallenge(_req) => {
                op_ok_rsp(PerformOpRsp::GetRootOfTrustChallenge(GetRootOfTrustChallengeResponse {
                    ret: [0u8; 16],
                }))
            }

            _ => error_rsp(ErrorCode::Unimplemented as i32),
        }
    }

    fn get_rpc_hardware_info(&self) -> Result<kmr_wire::rpc::HardwareInfo, Error> {
        match &self.rpc_info {
            RpcInfo::V2(rpc_info_v2) => Ok(kmr_wire::rpc::HardwareInfo {
                version_number: IRPC_V2,
                rpc_author_name: rpc_info_v2.author_name.to_string(),
                supported_eek_curve: rpc_info_v2.supported_eek_curve,
                unique_id: Some(rpc_info_v2.unique_id.to_string()),
                supported_num_keys_in_csr: MINIMUM_SUPPORTED_KEYS_IN_CSR,
            }),
            RpcInfo::V3(rpc_info_v3) => Ok(kmr_wire::rpc::HardwareInfo {
                version_number: IRPC_V3,
                rpc_author_name: rpc_info_v3.author_name.to_string(),
                supported_eek_curve: EekCurve::None,
                unique_id: Some(rpc_info_v3.unique_id.to_string()),
                supported_num_keys_in_csr: rpc_info_v3.supported_num_of_keys_in_csr,
            }),
        }
    }

    pub fn additional_attestation_info(&self) -> Option<&[u8]> {
        self.additional_attestation_info.as_deref()
    }

    pub fn set_additional_attestation_info(&mut self, info: Vec<u8>) -> bool {
        if self.additional_attestation_info.is_some() {
            false
        } else {
            self.additional_attestation_info = Some(info);
            true
        }
    }

    pub fn attestation_id_info(&self) -> Option<&AttestationIdInfo> {
        self.attestation_id_info.as_ref()
    }

    pub fn set_attestation_id_info(&mut self, info: AttestationIdInfo) -> bool {
        if self.attestation_id_info.is_some() {
            false
        } else {
            self.attestation_id_info = Some(info);
            true
        }
    }

    pub fn boot_info(&self) -> Option<&BootInfo> {
        self.boot_info.as_ref()
    }

    pub fn set_boot_info(&mut self, info: BootInfo) -> bool {
        if self.boot_info.is_some() {
            false
        } else {
            self.boot_info = Some(info);
            true
        }
    }

    pub fn hal_info(&self) -> Option<&HalInfo> {
        self.hal_info.as_ref()
    }

    pub fn set_hal_info(&mut self, info: HalInfo) -> bool {
        if self.hal_info.is_some() {
            false
        } else {
            self.hal_info = Some(info);
            true
        }
    }

    pub fn hw_info(&self) -> &HardwareInfo {
        &self.hw_info
    }

    pub fn rpc_info(&self) -> &RpcInfo {
        &self.rpc_info
    }

    pub fn rpc_device_info_cbor(&self) -> Result<Vec<u8>, Error> {
        let ids = self.attestation_id_info().ok_or_else(|| {
            km_err!(AttestationIdsNotProvisioned, "attestation ID info not available")
        })?;
        let boot_info = self
            .boot_info()
            .ok_or_else(|| km_err!(HardwareNotYetAvailable, "no boot info available"))?;
        let hal_info = self
            .hal_info()
            .ok_or_else(|| km_err!(HardwareNotYetAvailable, "HAL info not available"))?;
        let hw_info = self.hw_info();
        let rpc_info = self.rpc_info();

        let brand = String::from_utf8_lossy(&ids.brand);
        let manufacturer = String::from_utf8_lossy(&ids.manufacturer);
        let product = String::from_utf8_lossy(&ids.product);
        let model = String::from_utf8_lossy(&ids.model);
        let device = String::from_utf8_lossy(&ids.device);

        let bootloader_state = if boot_info.device_boot_locked { "locked" } else { "unlocked" };
        let vbmeta_digest = cbor::value::Value::Bytes(try_to_vec(&boot_info.verified_boot_hash)?);
        let vb_state = match boot_info.verified_boot_state {
            VerifiedBootState::Verified => "green",
            VerifiedBootState::SelfSigned => "yellow",
            VerifiedBootState::Unverified => "orange",
            VerifiedBootState::Failed => "red",
        };
        let security_level = match hw_info.security_level {
            SecurityLevel::TrustedEnvironment => "tee",
            SecurityLevel::Strongbox => "strongbox",
            l => {
                return Err(km_err!(
                    HardwareTypeUnavailable,
                    "security level {:?} not supported",
                    l
                ))
            }
        };

        let fused = match rpc_info {
            RpcInfo::V2(rpc_info_v2) => rpc_info_v2.fused,
            RpcInfo::V3(rpc_info_v3) => rpc_info_v3.fused,
        };

        let value = cbor!({
            "brand" => brand,
            "fused" => i32::from(fused),
            "model" => model,
            "device" => device,
            "product" => product,
            "vb_state" => vb_state,
            "os_version" => hal_info.os_version.to_string(),
            "manufacturer" => manufacturer,
            "vbmeta_digest" => vbmeta_digest,
            "security_level" => security_level,
            "boot_patch_level" => boot_info.boot_patchlevel,
            "bootloader_state" => bootloader_state,
            "system_patch_level" => hal_info.os_patchlevel,
            "vendor_patch_level" => hal_info.vendor_patchlevel,
        })?;
        serialize_cbor(&value)
    }
}

/// Create an OK response structure with the given inner response message.
fn op_ok_rsp(rsp: PerformOpRsp) -> PerformOpResponse {
    // Zero is OK in any context.
    PerformOpResponse { error_code: 0, rsp: Some(rsp) }
}

/// Create a response structure with the given error.
fn op_error_rsp(op: KeyMintOperation, err: Error) -> PerformOpResponse {
    warn!("failing {op:?} request with error {err:?}");
    if kmr_wire::is_rpc_operation(op) {
        // The IRemotelyProvisionedComponent HAL uses its own error space.
        let rpc_err: rpc::ErrorCode = match err.kind() {
            ErrorKind::Cbor(_) | ErrorKind::Der(_) | ErrorKind::Alloc(_) => rpc::ErrorCode::Failed,
            ErrorKind::Hal(_, _) | ErrorKind::Frp(_, _) => {
                error!("encountered non-RKP error on RKP method! {err:?}");
                rpc::ErrorCode::Failed
            }
            ErrorKind::Rpc(e, _) => *e,
        };
        error_rsp(rpc_err as i32)
    } else if kmr_wire::is_frp_operation(op) {
        // The IFactoryResetProtection HAL uses its own error space.
        let frp_err: FrpErrorCode = match err.kind() {
            ErrorKind::Cbor(_) | ErrorKind::Der(_) | ErrorKind::Alloc(_) => FrpErrorCode::Failed,
            ErrorKind::Hal(_, _) | ErrorKind::Rpc(_, _) => {
                error!("encountered non-FRP error on FRP method! {err:?}");
                FrpErrorCode::Failed
            }
            ErrorKind::Frp(e, _) => *e,
        };
        error_rsp(frp_err as i32)
    } else {
        let hal_err = match err.kind() {
            ErrorKind::Cbor(_) | ErrorKind::Der(_) => ErrorCode::InvalidArgument,
            ErrorKind::Hal(e, _) => *e,
            ErrorKind::Rpc(_, _) => {
                error!("encountered RKP error on non-RKP method! {err:?}");
                ErrorCode::InvalidArgument
            }
            ErrorKind::Frp(_, _) => {
                error!("encountered FRP error on non-FRP method! {err:?}");
                ErrorCode::InvalidArgument
            }
            ErrorKind::Alloc(_) => ErrorCode::MemoryAllocationFailed,
        };
        error_rsp(hal_err as i32)
    }
}

/// Create a response structure with the given error code.
fn error_rsp(error_code: i32) -> PerformOpResponse {
    PerformOpResponse { error_code, rsp: None }
}

/// Hand-encoded [`PerformOpResponse`] data for [`ErrorCode::UNKNOWN_ERROR`].
/// Does not perform CBOR serialization (and so is suitable for error reporting if/when
/// CBOR serialization fails).
fn invalid_cbor_rsp_data() -> [u8; 5] {
    [
        0x82, // 2-arr
        0x39, // nint, len 2
        0x03, // 0x3e7(999)
        0xe7, // = -1000
        0x80, // 0-arr
    ]
}

/// Helper function to serialize a `cbor::value::Value` into bytes.
fn serialize_cbor(cbor_value: &cbor::value::Value) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    cbor::ser::into_writer(cbor_value, &mut buf).map_err(|_e| km_err!(EncodingError, "cbor"))?;
    Ok(buf)
}
