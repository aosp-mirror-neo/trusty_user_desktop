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

use coset::{CoseError, TaggedCborSerializable};
use finger_guard::crypto;
use finger_guard::error::{ServiceError, ServiceResult};
use kmr_common::wire::keymint::BootInfo;
use kmr_common::wire::legacy::{self, TrustyKeymasterSecureOperation};
use kmr_common::wire::{
    AsCborValue, CborError, GetRootOfTrustRequest, PerformOpReq, PerformOpResponse, PerformOpRsp,
};
use std::ffi::CStr;
use tipc::{Deserialize, Handle, Serialize, Serializer, TipcError};
use trusty_std::alloc::TryAllocFrom;
use zerocopy::FromBytes;

// The port string for keymint's legacy keymaster interface.
const KEYMINT_KM_PORT: &CStr = c"com.android.trusty.keymaster.secure";
// The port string for keymint's normal service interface.
const KEYMINT_PORT: &CStr = c"com.android.trusty.keymint";

// Create a byte buffer contains the serialized GetAuthTokenKeyRequest.
fn get_auth_token_key_request() -> Vec<u8> {
    ((TrustyKeymasterSecureOperation::GetAuthTokenKey as u32) << legacy::TRUSTY_CMD_SHIFT)
        .to_ne_bytes()
        .to_vec()
}

// Extend Result with a function that can map trusty IPC errors to service errors.
trait MapTipcErrExt<T> {
    fn wrap_tipc_err(self, msg: &'static str) -> ServiceResult<T>;
}
impl<T> MapTipcErrExt<T> for Result<T, TipcError> {
    fn wrap_tipc_err(self, msg: &'static str) -> ServiceResult<T> {
        self.map_err(|e| ServiceError::TipcError(msg, Box::new(e)))
    }
}

// Extend Result with a function that can map Cbor/Cose errors to service errors.
trait MapCborErrExt<T> {
    fn wrap_cbor_err(self, msg: &'static str) -> ServiceResult<T>;
}
impl<T> MapCborErrExt<T> for Result<T, CborError> {
    fn wrap_cbor_err(self, msg: &'static str) -> ServiceResult<T> {
        self.map_err(|e| ServiceError::CborError(msg, Box::new(e)))
    }
}
impl<T> MapCborErrExt<T> for Result<T, CoseError> {
    fn wrap_cbor_err(self, msg: &'static str) -> ServiceResult<T> {
        self.map_err(|e| ServiceError::CborError(msg, Box::new(e)))
    }
}

// Since we are initially only interested in sending/receiving the GetAuthTokenKey
// request/response, which have simple layouts, the hardcoded request/response
// encoding and parsing is much easier to produce and maintain. The full
// service interface is a legacy Keymaster interface without an AIDL
// specification. Having a generialized request and response serde impl for
// the entire interface is not worth it.
// KMMessage implements a naive serde for a byte buffer. This allows we send
// and receive a byte buffer directly with a tipc::Handle object so that we can
// plug in the hardcoded request encoder and response decoder.
// We also use KMMessage for sending/receiving the GetRootOfTrust request/response.
struct KMMessage(Vec<u8>);
const MAX_MESSAGE_SIZE: usize = 1024;

impl<'s> Serialize<'s> for KMMessage {
    fn serialize<'a: 's, S: Serializer<'s>>(
        &'a self,
        serializer: &mut S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_slice())
    }
}

impl Deserialize for KMMessage {
    type Error = TipcError;
    const MAX_SERIALIZED_SIZE: usize = MAX_MESSAGE_SIZE;

    fn deserialize(bytes: &[u8], _handles: &mut [Option<Handle>]) -> tipc::Result<Self> {
        Ok(KMMessage(Vec::try_alloc_from(bytes)?))
    }
}

fn raw_get_auth_token_key_response() -> tipc::Result<Vec<u8>> {
    let session = Handle::connect(KEYMINT_KM_PORT)?;
    let req = KMMessage(get_auth_token_key_request());
    session.send(&req)?;
    let mut buf = [0u8; MAX_MESSAGE_SIZE];
    let resp: KMMessage = session.recv(&mut buf)?;
    Ok(resp.0)
}

#[derive(FromBytes)]
#[repr(C)]
struct AuthTokenKeyMessage {
    _raw_cmd: u32,
    auth_token_key: crypto::Key,
}

#[derive(FromBytes)]
#[repr(C)]
struct ErrorMessage {
    _raw_cmd: u32,
    error_code: u32,
}

// Parse the raw response of GetAuthTokenKey and returns the 32-byte auth token
// key if any.
pub fn get_auth_token_key() -> ServiceResult<crypto::Key> {
    let raw_response =
        raw_get_auth_token_key_response().wrap_tipc_err("Keymint connection failed")?;

    // For GetAuthTokenKey, the client has to distinguish between OK and error
    // responses by the size of the result byte array: 4+32 for OK, 4+4 for
    // error. C.f. system/keymint/wire/src/legacy.rs
    if let Ok(success_message) = AuthTokenKeyMessage::read_from_bytes(&raw_response) {
        Ok(success_message.auth_token_key)
    } else if let Ok(error_message) = ErrorMessage::read_from_bytes(&raw_response) {
        Err(ServiceError::KeymintError { cmd: "GetAuthTokenKey", code: error_message.error_code })
    } else {
        Err(ServiceError::KeymintBadResponse { cmd: "GetAuthTokenKey" })
    }
}

// Create a byte buffer contains the serialized GetRootOfTrustRequest.
fn get_root_of_trust_request() -> Vec<u8> {
    let challenge = [0u8; 16];
    let request = GetRootOfTrustRequest { challenge };
    let req_bytes = PerformOpReq::GetRootOfTrust(request)
        .into_vec()
        .expect("GetRootOfTrustRequest serialization failed");
    req_bytes
}

// Send the serialized GetRootOfTrustRequest and get a raw response.
fn raw_get_root_of_trust_response() -> tipc::Result<Vec<u8>> {
    let session = Handle::connect(KEYMINT_PORT)?;
    let req = KMMessage(get_root_of_trust_request());
    session.send(&req)?;
    let mut buf = [0u8; MAX_MESSAGE_SIZE];
    let resp: KMMessage = session.recv(&mut buf)?;
    Ok(resp.0)
}

// Parse the raw response of GetRootOfTrust to obtain BootInfo.
pub fn get_boot_info() -> ServiceResult<BootInfo> {
    let raw_response =
        raw_get_root_of_trust_response().wrap_tipc_err("Keymint connection failed")?;
    // Raw responses from keymint standard services are chunked. The first byte of each chunk
    // indicates whether there is a next chunk. Since GetRootOfTrust response is small enough to
    // fit in one chunk (4000 byte), the first byte of the raw response is always 0 and the rest
    // contains the cbor encoded service response.
    if raw_response[0] != 0u8 {
        return Err(ServiceError::KeymintBadResponse { cmd: "GetRootOfTrust" });
    }
    let response = PerformOpResponse::from_slice(&raw_response[1..])
        .wrap_cbor_err("GetRootOfTrust raw response decode failed")?;
    if let Some(PerformOpRsp::GetRootOfTrust(rsp)) = response.rsp {
        let cose_mac0 = coset::CoseMac0::from_tagged_slice(rsp.ret.as_slice())
            .wrap_cbor_err("GetRootOfTrustResponse decode as CoseMac0 failed")?;
        let payload =
            cose_mac0.payload.ok_or(ServiceError::KeymintBadResponse { cmd: "GetRootOfTrust" })?;
        BootInfo::from_tagged_slice(payload.as_slice())
            .wrap_cbor_err("CoseMac0 payload decode as BootInfo failed")
    } else {
        Err(ServiceError::KeymintBadResponse { cmd: "GetRootOfTrust" })
    }
}
