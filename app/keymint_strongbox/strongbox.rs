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

use crate::{operations, rkp};
use android_system_desktop_security_gsc::aidl::android::system::desktop::security::gsc::IGsc::IGsc;
use binder::Strong;
use gsc_svc_client::GscServiceClient;
use kmr_common::{Error, ErrorKind};
use kmr_wire::{frp::ErrorCode as FrpErrorCode, keymint::ErrorCode, *};
use log::{error, trace, warn};

pub struct StrongBox {
    tpm: Strong<dyn IGsc>,
}

impl Default for StrongBox {
    fn default() -> Self {
        Self { tpm: GscServiceClient::default().0 }
    }
}

impl StrongBox {
    /// Process a single serialized request, returning a serialized response.
    pub fn process(&mut self, req_data: &[u8]) -> Vec<u8> {
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
            PerformOpReq::DeviceBegin(req) => match operations::device_begin(req, &self.tpm) {
                Ok(resp) => op_ok_rsp(PerformOpRsp::DeviceBegin(resp)),
                Err(err) => op_error_rsp(KeyMintOperation::DeviceBegin, err),
            },
            PerformOpReq::OperationFinish(req) => {
                match operations::operation_finish(req, &self.tpm) {
                    Ok(resp) => op_ok_rsp(PerformOpRsp::OperationFinish(resp)),
                    Err(err) => op_error_rsp(KeyMintOperation::OperationFinish, err),
                }
            }
            PerformOpReq::OperationUpdate(req) => {
                match operations::operation_update(req, &self.tpm) {
                    Ok(resp) => op_ok_rsp(PerformOpRsp::OperationUpdate(resp)),
                    Err(err) => op_error_rsp(KeyMintOperation::OperationUpdate, err),
                }
            }
            PerformOpReq::RpcGenerateCertificateV2Request(req) => {
                match rkp::generate_certificate_request_v2(req, &self.tpm) {
                    Ok(resp) => op_ok_rsp(PerformOpRsp::RpcGenerateCertificateV2Request(resp)),
                    Err(err) => {
                        op_error_rsp(KeyMintOperation::RpcGenerateCertificateV2Request, err)
                    }
                }
            }
            PerformOpReq::RpcGenerateEcdsaP256KeyPair(_) => {
                let _ = rkp::generate_ecdsa_p256_keypair(&self.tpm);
                error_rsp(ErrorCode::Unimplemented as i32)
            }
            PerformOpReq::RpcGetHardwareInfo(_) => {
                let _ = rkp::get_hardware_info(&self.tpm);
                error_rsp(ErrorCode::Unimplemented as i32)
            }
            _ => error_rsp(ErrorCode::Unimplemented as i32),
        }
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
