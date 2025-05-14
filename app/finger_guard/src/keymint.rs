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
use kmr_common::wire::legacy::{self, TrustyKeymasterSecureOperation};
use std::ffi::CStr;
use tipc::{Deserialize, Handle, Serialize, Serializer, TipcError};
use trusty_std::alloc::TryAllocFrom;
use zerocopy::FromBytes;

// The port string for keymint.
const KEYMINT_PORT: &CStr = c"com.android.trusty.keymaster.secure";

// Create a byte buffer contains the serialized GetAuthTokenKeyRequest.
fn get_auth_token_key_request() -> Vec<u8> {
    ((TrustyKeymasterSecureOperation::GetAuthTokenKey as u32) << legacy::TRUSTY_CMD_SHIFT)
        .to_ne_bytes()
        .to_vec()
}

// Since we are only interested in sending/receiving the GetAuthTokenKey
// request/response, which have simple layouts, the hardcoded request/response
// encoding and parsing is much easier to produce and maintain. The full
// service interface is a legacy Keymaster interface without an AIDL
// specification. Having a generialized request and response serde impl for
// the entire interface is not worth it.
// KMMessage implements a naive serde for a byte buffer. This allows we send
// and receive a byte buffer directly with a tipc::Handle object so that we can
// plug in the hardcoded request encoder and response decoder.
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
    let session = Handle::connect(KEYMINT_PORT)?;
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
    auth_token_key: [u8; 32],
}

#[derive(FromBytes)]
#[repr(C)]
struct ErrorMessage {
    _raw_cmd: u32,
    error_code: u32,
}

// Parse the raw response of GetAuthTokenKey and returns the 32-byte auth token
// key if any.
pub fn get_auth_token_key() -> ServiceResult<[u8; 32]> {
    let raw_response = raw_get_auth_token_key_response()
        .map_err(|e| ServiceError::TipcError("Keymint connection failed", e))?;

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
