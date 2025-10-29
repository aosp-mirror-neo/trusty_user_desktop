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

use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::{
    ClientSessionResponse::ClientSessionResponse, IClientSession::BnClientSession,
    IClientSession::IClientSession, InitResponse::InitResponse,
    PrepareAuthSessionResponse::PrepareAuthSessionResponse,
    SdcpClientSessionResponse::SdcpClientSessionResponse,
};
use binder::BinderFeatures;

/// Trait that is implemented to support exporting a specific field for an AIDL type.
///
/// For types where there is a simple "1 internal struct -> 1 aidl struct" this isn't necessary and
/// implementing From is a good choice, but for "2+ internal structs -> 1 aidl struct" situations
/// this does not work because no single individual struct can produce the complete AIDL type.
///
/// To work around this we use this generic trait which is intended to indicate that you can be
/// converted to produce a single field of the output type. Thus this trait has three generic
/// parameters: the type of the struct being exported, the field being exported as represented by
/// its offset within the struct, and the type of the field. Note that the first two parameters
/// are purely indicator parameters and are not actually used by implementations.
pub trait ExportAidlField<AidlType, const OFFSET: usize, FieldType> {
    /// Export the relevant contents of Self into the AidlType.OFFSET.
    fn export(&self) -> FieldType;
}

/// Macro that can be used to simplify ExportAidlField declarations.
///
/// While implementing field export is just a simple "implement this trait" pattern, writing out the
/// actual name of the trait is not particularly readable due to the use of field offsets to
/// represent the field being exported. Thus, this macro is provided to encapsulate that.
///
/// Given a struct MyStruct that wants to export fieldName on AidlStruct you write this as:
///
///   impl_export!(MyStruct(self) => AidlStruct.fieldName as FieldType {
///       ... code to do the export goes here ...
///   });
///
/// This will fill in the somewhat messy trait declaration and export function, implementing it with
/// the block of code you supply. Note that you need to explicitly specify the name you want to use
/// for the "self" parameter due to how macro hygiene works, but it should be "self".
macro_rules! impl_export {
    ($impltype:ident($selfname:ident) => $external:ident.$field:ident as $ftype:ty {$($body:tt)*}) => {
        impl crate::aidl::ExportAidlField<$external, {std::mem::offset_of!($external, $field)}, $ftype> for $impltype {
            fn export(&$selfname) -> $ftype {
                $($body)*
            }
        }
    }
}
pub(crate) use impl_export;

/// Simple macro that calls export on a given value for a specific AIDL type + field.
///
/// Normally this is unnecessary and you can just call export() directly, but if type exports
/// multiple fields it may be ambiguous which export you want to call.
macro_rules! export_field {
    ($value:expr => $external:ident.$field:ident) => {
        <_ as crate::aidl::ExportAidlField<
            $external,
            { std::mem::offset_of!($external, $field) },
            _,
        >>::export($value)
    };
}
pub(crate) use export_field;

/// Simple macro to spell the name of an "&impl ExportAidlField" parameter in functions.
///
/// This is intended for use by the various factory functions that are constructing an AIDL from a
/// set of internal types. Generally such functions want to accept a "anything that implements the
/// export of this field" reference and this spells that type in a somewhat more legible way:
macro_rules! ref_to_impl_export {
    ($external:ident.$field:ident as $ftype:ty) => {
        &impl ExportAidlField<$external, {std::mem::offset_of!($external, $field)}, $ftype>
    }
}

/// Construct a handshake response.
pub fn make_init_response(
    server_public_key: ref_to_impl_export!(InitResponse.serverPublicKey as Vec<u8>),
    pk_mac: ref_to_impl_export!(InitResponse.pkMac as Vec<u8>),
) -> InitResponse {
    InitResponse { serverPublicKey: server_public_key.export(), pkMac: pk_mac.export() }
}

/// Construct a session response.
pub fn make_client_session_response(
    nonce: ref_to_impl_export!(ClientSessionResponse.nonce as Vec<u8>),
    wrapped_tpm_seed: Vec<u8>,
    iv: ref_to_impl_export!(ClientSessionResponse.iv as Vec<u8>),
    tag: ref_to_impl_export!(ClientSessionResponse.tag as Vec<u8>),
    client_session: Option<impl IClientSession>,
) -> ClientSessionResponse {
    ClientSessionResponse {
        nonce: nonce.export(),
        wrappedTpmSeed: wrapped_tpm_seed,
        iv: iv.export(),
        tag: tag.export(),
        clientSession: client_session
            .map(|s| BnClientSession::new_binder(s, BinderFeatures::default())),
    }
}

/// Construct a sdcp session response.
pub fn make_sdcp_client_session_response(
    server_public_key: ref_to_impl_export!(SdcpClientSessionResponse.serverPublicKey as Vec<u8>),
    nonce: ref_to_impl_export!(SdcpClientSessionResponse.nonce as Vec<u8>),
    wrapped_tpm_seed: Vec<u8>,
    iv: ref_to_impl_export!(SdcpClientSessionResponse.iv as Vec<u8>),
    tag: ref_to_impl_export!(SdcpClientSessionResponse.tag as Vec<u8>),
    client_session: Option<impl IClientSession>,
) -> SdcpClientSessionResponse {
    SdcpClientSessionResponse {
        serverPublicKey: server_public_key.export(),
        nonce: nonce.export(),
        wrappedTpmSeed: wrapped_tpm_seed,
        iv: iv.export(),
        tag: tag.export(),
        clientSession: client_session
            .map(|s| BnClientSession::new_binder(s, BinderFeatures::default())),
    }
}

/// Construct a new prepare_auth_session response.
pub fn make_prepare_auth_session_response(
    nonce: ref_to_impl_export!(PrepareAuthSessionResponse.nonce as [u8; 32]),
    mac: ref_to_impl_export!(PrepareAuthSessionResponse.mac as Vec<u8>),
) -> PrepareAuthSessionResponse {
    PrepareAuthSessionResponse { nonce: nonce.export(), mac: mac.export() }
}

#[cfg(test)]
mod test {
    use super::{
        make_client_session_response, make_init_response,
        make_prepare_auth_session_response,
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
        let public_key_bytes: Vec<u8> = (1..=65).collect();
        let public_key = crypto::P256Point::import(public_key_bytes.as_slice()).unwrap();
        let hmac_bytes: Vec<u8> = (1..=32).map(|x| x * 2).collect();
        let hmac = crypto::Hmac::read_from_bytes(hmac_bytes.as_slice()).unwrap();
        let response = make_init_response(&public_key, &hmac);
        assert_eq!(response.serverPublicKey, public_key_bytes);
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
}
