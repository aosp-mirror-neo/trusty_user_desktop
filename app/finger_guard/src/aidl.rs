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

//! Traits and utilities for moving data into and out of AIDL interface types.

use crate::crypto;
use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::{
    ClientSessionResponse::ClientSessionResponse,
    FinishEnrollSessionResponse::FinishEnrollSessionResponse, IClientSession::BnClientSession,
    IClientSession::IClientSession, InitResponse::InitResponse,
    PrepareAuthSessionResponse::PrepareAuthSessionResponse,
    PrepareEnrollSessionResponse::PrepareEnrollSessionResponse,
};
use binder::BinderFeatures;

/// Trait that is implemented to support exporting data to a particular AIDL type.
///
/// This relies on the exporting class being passed a mutable reference to a partially initialized
/// AIDL type and filling in the appropriate subset of fields which it can populate. This is not
/// entirely ideal because it mean the type system can't guarantee that the structure is truly
/// initialized properly.
///
/// For types where there's a simple "1 internal struct -> 1 aidl struct" it is better to use a
/// From trait, but for situations where it takes multiple types to create the AIDL type this
/// is a reasonable compromise.
pub trait ExportToAidl<T> {
    /// Export the relevant contexts of Self into the `out` parameter.
    ///
    /// The function should not assume that the output parameter is in any particular state when
    /// being passed in. When an object of type T is being exported to by multiple source
    /// ExportToAidl objects, the result should be the same regardless of the order in which the
    /// export functions are called.
    fn export(&self, out: &mut T);
}

/// Construct a handshake response.
pub fn make_init_response(server_public_key: Vec<u8>, pk_mac: &crypto::Hmac) -> InitResponse {
    let mut response = InitResponse { serverPublicKey: server_public_key, ..Default::default() };
    pk_mac.export(&mut response);
    response
}

/// Construct a session response.
pub fn make_client_session_response(
    nonce: &crypto::Nonce,
    wrapped_tpm_seed: Vec<u8>,
    iv: &crypto::Iv,
    tag: &crypto::Aes256Tag,
    client_session: Option<impl IClientSession>,
) -> ClientSessionResponse {
    let mut response = ClientSessionResponse {
        wrappedTpmSeed: wrapped_tpm_seed,
        clientSession: client_session
            .map(|s| BnClientSession::new_binder(s, BinderFeatures::default())),
        ..Default::default()
    };
    nonce.export(&mut response);
    iv.export(&mut response);
    tag.export(&mut response);
    response
}

/// Construct a new prepare_auth_session response.
pub fn make_prepare_auth_session_response(
    nonce: &crypto::Nonce,
    mac: &crypto::Hmac,
) -> PrepareAuthSessionResponse {
    let mut response = PrepareAuthSessionResponse::default();
    nonce.export(&mut response);
    mac.export(&mut response);
    response
}

/// Construct a new prepare_enroll_session response.
pub fn make_prepare_enroll_session_response(mac: &crypto::Hmac) -> PrepareEnrollSessionResponse {
    let mut response = PrepareEnrollSessionResponse::default();
    mac.export(&mut response);
    response
}

/// Construct a new finish_enroll_session response.
pub fn make_finish_enroll_session_response(mac: &crypto::Hmac) -> FinishEnrollSessionResponse {
    let mut response = FinishEnrollSessionResponse::default();
    mac.export(&mut response);
    response
}

#[cfg(test)]
mod test {
    use super::{
        make_client_session_response, make_finish_enroll_session_response, make_init_response,
        make_prepare_auth_session_response, make_prepare_enroll_session_response,
    };
    use crate::crypto;
    use std::array;
    use zerocopy::FromBytes;
    use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::IClientSession::BpClientSession;

    // In general all of these tests deliberately make their input data non-zero. Otherwise it's
    // difficult to distinguish between fields which were correctly populated and ones which were
    // simply default-initialized.

    #[test]
    fn test_make_init_response() {
        let public_key: Vec<u8> = (1..=32).collect();
        let hmac_bytes: Vec<u8> = (1..=32).map(|x| x * 2).collect();
        let hmac = crypto::Hmac::read_from_bytes(hmac_bytes.as_slice()).unwrap();
        let response = make_init_response(public_key.clone(), &hmac);
        assert_eq!(response.serverPublicKey, public_key);
        assert_eq!(response.pkMac, hmac_bytes);
    }

    #[test]
    fn test_make_client_session_response() {
        let nonce_bytes: [u8; 32] = array::from_fn(|x| x as u8);
        let nonce = crypto::Nonce::read_from_bytes(&nonce_bytes).unwrap();
        let wrapped_tpm_seed: Vec<u8> = (1..=32).map(|x| x * 2).collect();
        let iv_bytes: [u8; 12] = array::from_fn(|x| x as u8 * 3);
        let iv = crypto::Iv::read_from_bytes(&iv_bytes).unwrap();
        let tag_bytes: [u8; 16] = array::from_fn(|x| x as u8 * 4);
        let tag = crypto::Aes256Tag::read_from_bytes(&tag_bytes).unwrap();
        let response = make_client_session_response(
            &nonce,
            wrapped_tpm_seed.clone(),
            &iv,
            &tag,
            None::<BpClientSession>,
        );
        assert_eq!(response.nonce, nonce_bytes);
        assert_eq!(response.wrappedTpmSeed, wrapped_tpm_seed);
        assert_eq!(response.iv, iv_bytes);
        assert_eq!(response.tag, tag_bytes);
    }

    #[test]
    fn test_make_prepare_auth_session_response() {
        let nonce_bytes: [u8; 32] = array::from_fn(|x| x as u8);
        let nonce = crypto::Nonce::read_from_bytes(&nonce_bytes).unwrap();
        let hmac_bytes: Vec<u8> = (1..=32).map(|x| x * 2).collect();
        let hmac = crypto::Hmac::read_from_bytes(hmac_bytes.as_slice()).unwrap();
        let response = make_prepare_auth_session_response(&nonce, &hmac);
        assert_eq!(response.nonce, nonce_bytes);
        assert_eq!(response.mac, hmac_bytes);
    }

    #[test]
    fn test_make_prepare_enroll_session_response() {
        let hmac_bytes: Vec<u8> = (1..=32).collect();
        let hmac = crypto::Hmac::read_from_bytes(hmac_bytes.as_slice()).unwrap();
        let response = make_prepare_enroll_session_response(&hmac);
        assert_eq!(response.mac, hmac_bytes);
    }

    #[test]
    fn test_make_finish_enroll_session_response() {
        let hmac_bytes: Vec<u8> = (1..=32).collect();
        let hmac = crypto::Hmac::read_from_bytes(hmac_bytes.as_slice()).unwrap();
        let response = make_finish_enroll_session_response(&hmac);
        assert_eq!(response.mac, hmac_bytes);
    }
}
