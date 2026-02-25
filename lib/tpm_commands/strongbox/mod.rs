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

//! Structs and items that define TPM communications with the GSC

#![allow(clippy::result_unit_err)]

use crate::{TpmvRequest, TpmvRequestBuild, NO_SESSION_TAG};
use kmr_common::{km_err, Error};
use kmr_wire::{
    keymint::{Certificate, KeyCreationResult, KeyMintHardwareInfo, SecurityLevel},
    *,
};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, BE, I32, I64, LE, U16, U32,
};

macro_rules! impl_tpmv_request {
    ($kmr_wire_req:ident) => {
        impl TpmvRequest for Request {
            const TAG: U16<BE> = NO_SESSION_TAG;
            const COMMAND_CODE: U16<BE> = U16::new($kmr_wire_req::CODE as u16);
            const ORDINAL: U32<BE> = VENDOR_COMMAND_STRONGBOX;
            type TpmvResponse = Response;
        }
    };
}

pub mod key_param;

/// Type alias to work around macro issues.
pub type U32LE = U32<LE>;

/// Type alias to work around macro issues.
pub type I64LE = I64<LE>;

// The word size used by the GSC.
const WORD_SIZE: usize = size_of::<U32LE>();

/// The ordinal value that is used for all strongbox commands
const VENDOR_COMMAND_STRONGBOX: U32<BE> = U32::new(0x20000001);

/// Helper function to serialize a u32le length into a slice.
fn copy_u32le(dest: &mut [u8], len: usize) -> Result<&mut [u8], Error> {
    let (len_bytes, suffix) =
        dest.split_at_mut_checked(size_of::<U32LE>()).ok_or(km_err!(EncodingError, ""))?;
    len_bytes.copy_from_slice(
        &U32LE::new(len.try_into().map_err(|_| km_err!(EncodingError, ""))?).to_bytes(),
    );
    Ok(suffix)
}

/// Helper function to serialize a u32le length prefixed slice.
fn copy_u32le_prefixed_slice<'a>(
    mut dest: &'a mut [u8],
    data: &[u8],
    word_padding: bool,
) -> Result<&'a mut [u8], Error> {
    dest = copy_u32le(dest, data.len())?;
    let dest_len = if word_padding { data.len().next_multiple_of(WORD_SIZE) } else { data.len() };
    let (dest, suffix) = dest.split_at_mut_checked(dest_len).ok_or(km_err!(EncodingError, ""))?;
    if dest.len() != dest_len || dest_len < data.len() {
        return Err(km_err!(
            EncodingError,
            "copy_u32le_prefixed_slice, dest {}, needed {}, data {}",
            dest.len(),
            dest_len,
            data.len()
        ));
    }
    dest[..data.len()].copy_from_slice(data);
    dest[data.len()..].fill(0);
    Ok(suffix)
}

/// Helper function to deserialize a u32le length from a slice.
fn get_u32le(dest: &mut [u8]) -> Result<(&mut [u8], &mut U32LE), Error> {
    let (len_bytes, suffix) =
        dest.split_at_mut_checked(size_of::<U32LE>()).ok_or(km_err!(EncodingError, "get_u32le"))?;
    Ok((suffix, U32LE::mut_from_bytes(len_bytes).map_err(|_| km_err!(EncodingError, "U32LE"))?))
}

/// Helper function to deserialize a u32le byte length prefixed slice.
fn get_u32le_prefixed_slice(dest: &mut [u8]) -> Result<(&mut [u8], &mut U32LE, &mut [u8]), Error> {
    let (suffix, len) = get_u32le(dest)?;
    let (ret, suffix) = suffix
        .split_at_mut_checked(len.get() as usize)
        .ok_or(km_err!(EncodingError, "u32le_prefixed_slice"))?;
    Ok((suffix, len, ret))
}

/// A GSC representation of kmr::rpc::MacedPublicKey
pub struct MacedPublicKey {
    /// Length of the following MACed key.
    pub maced_key_len_bytes: U32LE,
    /// The MACed public key data, padded to a 4-byte boundary.
    pub maced_key: [u8],
}

impl MacedPublicKey {
    /// The byte size of a MacedPublicKey with the specified key length in bytes.
    pub const fn expected_size(key_len_bytes: usize) -> usize {
        WORD_SIZE + key_len_bytes.next_multiple_of(WORD_SIZE)
    }
}

/// Creates a certificate signing request to be sent to the provisioning server.
/// Input Buffer (`buf`) Format:
///
/// The input buffer is a sequence of fields, all 32-bit aligned.
/// - [ 4 bytes ] uint32_t key_count: Number of MACed public keys.
///   @param in MacedPublicKey[] keysToSign contains the set of keys to certify.
///   The IRemotelyProvisionedComponent must validate the MACs on each key.  If any
///   entry in the array lacks a valid MAC, the method must return
///   STATUS_INVALID_MAC.  This method must not accept test keys. If any entry in
///   the array is a test key, the method must return
/// - [ n times ] Repeated for each key:
///   - [ 4 bytes ] uint32_t maced_key_len_bytes: Length of the following
///     MACed key.
///   - [ m bytes ] uint8_t maced_key[]: The MACed public key data, padded
///     to a 4-byte boundary.
///
/// Strongbox-subset specific:
/// - [ 4 bytes ] uint32_t device_info_len_bytes: Length of the DeviceInfo.
/// - [ q bytes ] uint8_t device_info[]: The CBOR-encoded DeviceInfo data.
///   In the DeviceInfo map fields:
///    - "security_level": "strongbox",
///    - "vb_state": "green",
///    - "bootloader_state": "locked"
///
/// have to be placed last, as future version would append these fields based
/// on the actual GSC state.
pub mod generate_certificate_request_v2 {
    use super::*;

    /// Struct that captures the parameters needed to make a generate_certificate_request_v2::Request.
    pub struct RequestBuildParams {
        /// The request being converted.
        pub request: kmr_wire::GenerateCertificateRequestV2Request,
        /// The device info bytes that are associated with the request.
        pub device_info: Vec<u8>,
    }

    /// The GSC equivalent of a kmr_wire::GenerateCertificateRequestV2Request.
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request {
        /// Number of MACed public keys.
        pub key_count: U32LE,
        /// Trailing bytes.
        pub suffix: [u8],
    }

    impl_tpmv_request!(GenerateCertificateRequestV2Request);

    impl TpmvRequestBuild for Request {
        type BuildParams = RequestBuildParams;

        type Err = Error;

        fn expected_size(params: &Self::BuildParams) -> Result<u32, Self::Err> {
            let static_size = 3 * WORD_SIZE;
            let mut maced_keys_size = 0usize;
            for key_to_sign in params.request.keys_to_sign.iter() {
                maced_keys_size = maced_keys_size
                    .checked_add(MacedPublicKey::expected_size(key_to_sign.maced_key.len()))
                    .ok_or(km_err!(EncodingError, ""))?
            }
            static_size
                .checked_add(maced_keys_size)
                .ok_or(km_err!(EncodingError, ""))?
                .checked_add(params.request.challenge.len().next_multiple_of(WORD_SIZE))
                .ok_or(km_err!(EncodingError, ""))?
                .checked_add(params.device_info.len().next_multiple_of(WORD_SIZE))
                .ok_or(km_err!(EncodingError, ""))?
                .try_into()
                .map_err(|_| km_err!(EncodingError, ""))
        }

        fn init(&mut self, params: Self::BuildParams) -> Result<(), Self::Err> {
            let RequestBuildParams { request, device_info } = params;
            self.key_count = U32LE::new(
                (request.keys_to_sign.len()).try_into().map_err(|_| km_err!(InvalidKeyBlob, ""))?,
            );

            let mut suffix = &mut self.suffix;
            for key_to_sign in request.keys_to_sign.iter() {
                suffix = copy_u32le_prefixed_slice(suffix, &key_to_sign.maced_key, true)?;
            }

            suffix = copy_u32le_prefixed_slice(suffix, &request.challenge, true)?;
            suffix = copy_u32le_prefixed_slice(suffix, &device_info, true)?;

            if !suffix.is_empty() {
                return Err(km_err!(EncodingError, ""));
            }

            Ok(())
        }
    }

    /// A struct of references to the various fields in a Request.
    pub struct BufferedRequest<'a> {
        /// Number of MACed public keys.
        pub key_count: &'a mut U32LE,
        /// A list of MACed public keys.
        pub keys_to_sign: Vec<&'a mut MacedPublicKey>,
        /// Length of the challenge.
        pub challenge_len_bytes: &'a mut U32LE,
        /// The challenge data, padded to a 4-byte boundary.
        pub challenge: &'a [u8],
        /// Length of the DeviceInfo.
        pub device_info_length_bytes: &'a mut U32LE,
        /// The CBOR-encoded DeviceInfo data.
        pub device_info: &'a [u8],
    }

    /// The GSC equivalent of kmr_wire::GenerateCertificateRequestV2Response
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// Returned bytes.
        pub ret: [u8],
    }

    impl TryFrom<&mut Response> for kmr_wire::GenerateCertificateRequestV2Response {
        type Error = Error;

        /// Convert a response into a kmr_wire::GenerateCertificateRequestV2Response.
        fn try_from(
            response: &mut Response,
        ) -> Result<kmr_wire::GenerateCertificateRequestV2Response, Error> {
            Ok(kmr_wire::GenerateCertificateRequestV2Response { ret: response.ret.to_vec() })
        }
    }
}

/// Vendor TPM command to enable strongbox
pub mod enable_strongbox {
    use super::*;

    /// This command has no inputs, so Request is an empty struct.
    #[derive(Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request {
        /// Flag to enable strongbox.
        pub enable: u8,
    }

    impl TpmvRequest for Request {
        const TAG: U16<BE> = NO_SESSION_TAG;
        const COMMAND_CODE: U16<BE> = U16::new(0x50u16);
        const ORDINAL: U32<BE> = crate::VENDOR_COMMAND_ORDINAL;
        type TpmvResponse = Response;
    }

    /// Represents a response from a [`Request`]
    #[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response;
}

/// Vendor TPM command representing a strongbox generate ecdsa P256 keypair request.
pub mod generate_ecdsa_p256_keypair {
    use super::*;

    /// This command has no inputs, so Request is an empty struct.
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request;

    impl_tpmv_request!(GenerateEcdsaP256KeyPairRequest);

    impl TpmvRequestBuild for Request {
        type BuildParams = kmr_wire::GenerateEcdsaP256KeyPairRequest;

        type Err = Error;

        fn expected_size(_params: &Self::BuildParams) -> Result<u32, Self::Err> {
            Ok(0u32)
        }

        fn init(&mut self, _params: Self::BuildParams) -> Result<(), Self::Err> {
            Ok(())
        }
    }

    /// Represents a response from a [`Request`]
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// suffix
        pub suffix: [u8],
    }

    impl TryFrom<&mut Response> for kmr_wire::GenerateEcdsaP256KeyPairResponse {
        type Error = Error;

        /// Convert a response into a kmr_wire::GenerateEcdsaP256KeyPairResponse.
        fn try_from(
            response: &mut Response,
        ) -> Result<kmr_wire::GenerateEcdsaP256KeyPairResponse, Error> {
            let view = BufferedResponse::try_from(response)?;
            Ok(kmr_wire::GenerateEcdsaP256KeyPairResponse {
                maced_public_key: rpc::MacedPublicKey { maced_key: view.maced_key.to_vec() },
                ret: view.key_blob.to_vec(),
            })
        }
    }

    /// A struct of references to the various fields in a Response.
    pub struct BufferedResponse<'a> {
        /// Key blob data.
        pub key_blob: &'a mut [u8],
        /// Size of MACed key in bytes.
        pub maced_key_bytes: &'a mut U32LE,
        /// MACed key bytes.
        pub maced_key: &'a mut [u8],
    }

    impl<'a> TryFrom<&'a mut Response> for BufferedResponse<'a> {
        type Error = Error;
        fn try_from(response: &'a mut Response) -> Result<BufferedResponse<'a>, Self::Error> {
            // Peek into key blob to get size that follows in words.
            let key_blob_words = U32LE::ref_from_prefix(&response.suffix[0..size_of::<u32>()])
                .map_err(|_| km_err!(EncodingError, "word length"))?
                .0
                .get() as usize;
            let (key_blob, suffix) = response
                .suffix
                .split_at_mut_checked((key_blob_words + 1) * WORD_SIZE)
                .ok_or(km_err!(EncodingError, "split response"))?;
            let (suffix, maced_key_bytes, maced_key) = get_u32le_prefixed_slice(suffix)?;
            if suffix.len() + maced_key.len() > maced_key.len().next_multiple_of(WORD_SIZE) {
                return Err(km_err!(EncodingError, "trailing bytes"));
            }

            Ok(BufferedResponse { key_blob, maced_key_bytes, maced_key })
        }
    }
}

/// Vendor TPM command representing a strongbox generate key request.
/// Input Buffer (`buf`):
/// A serialized list of Key parameters(tags).
/// - [ 4 bytes ] uint32_t tags_len_words: The size of the tag list that
///   follows, in 32-bit words.
/// - [ n bytes ] Serialized KeyMint tags. Each tag consists of a 32-bit tag
///   word followed by an optional, 32-bit aligned payload.
///
/// Output Buffer (`buf`):
/// A KeyCreationResult structure containing the key blob and an empty
/// certificate chain.
/// - [ 4 bytes ] uint32_t key_blob_total_words: Total size of the key blob
///   and characteristics that follow, in 32-bit words.
/// - [ n bytes ] Key blob, containing HW and SW enforced KeyCharacteristics.
///   Note: that key blob include KeyCharacteristics as its part, but in AIDL
///   KeyCharacteristics are returned separately as key blob format is opaque.
pub mod generate_key {
    use crate::strongbox::key_param::characteristics_from_key_blob;

    use super::*;

    /// This command has no inputs, so Request is an empty struct.
    #[derive(Debug, Eq, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request {
        /// The size of the tag list that follows, in 32-bit words.
        pub tags_len_words: U32LE,
        /// The trailing bytes
        pub suffix: [u8],
    }

    impl TpmvRequestBuild for Request {
        type BuildParams = GenerateKeyRequest;

        type Err = Error;

        fn expected_size(params: &Self::BuildParams) -> Result<u32, Self::Err> {
            let static_size = WORD_SIZE * 2; // Attestation key size and issuer size.
            let (attestation_key_size, issuer_subject_size) = params
                .attestation_key
                .as_ref()
                .map_or((0, 0), |a| (a.key_blob.len(), a.issuer_subject_name.len()));

            // We expect the key blob size to be aligned to the word boundary
            if attestation_key_size % WORD_SIZE != 0 {
                return Err(km_err!(EncodingError, "attestation_key not padded correctly"));
            }

            static_size
                .checked_add(key_param::expected_size(&params.key_params))
                .ok_or(km_err!(EncodingError, ""))?
                .checked_add(attestation_key_size)
                .ok_or(km_err!(EncodingError, ""))?
                .checked_add(issuer_subject_size.next_multiple_of(WORD_SIZE))
                .ok_or(km_err!(EncodingError, ""))?
                .try_into()
                .map_err(|_| km_err!(EncodingError, ""))
        }

        fn init(&mut self, params: Self::BuildParams) -> Result<(), Self::Err> {
            self.tags_len_words = U32LE::new(
                (key_param::expected_size(&params.key_params) / WORD_SIZE)
                    .try_into()
                    .map_err(|_| km_err!(EncodingError, ""))?,
            );

            let remainder = key_param::serialize_key_params(&mut self.suffix, &params.key_params);
            if let Some(attestation_key) = params.attestation_key {
                let (attest_key, suffix) = remainder
                    .split_at_mut_checked(attestation_key.key_blob.len())
                    .ok_or(km_err!(EncodingError, "split response"))?;
                attest_key.copy_from_slice(&attestation_key.key_blob);
                let suffix =
                    copy_u32le_prefixed_slice(suffix, &attestation_key.issuer_subject_name, true)?;
                if !suffix.is_empty() {
                    return Err(km_err!(EncodingError, ""));
                }
            } else if !remainder.is_empty() {
                return Err(km_err!(EncodingError, ""));
            }

            Ok(())
        }
    }

    impl_tpmv_request!(GenerateKeyRequest);

    /// Represents a response from a [`Request`]
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// The returned key.
        pub suffix: [u8],
    }

    impl TryFrom<&mut Response> for kmr_wire::GenerateKeyResponse {
        type Error = Error;

        /// Convert a response into a kmr_wire::GenerateKeyResponse.
        fn try_from(response: &mut Response) -> Result<kmr_wire::GenerateKeyResponse, Error> {
            let view = BufferedResponse::try_from(response)?;
            Ok(kmr_wire::GenerateKeyResponse {
                ret: KeyCreationResult {
                    key_blob: view.key_blob.to_vec(),
                    key_characteristics: characteristics_from_key_blob(view.key_blob)?,
                    certificate_chain: if view.cert_chain.is_empty() {
                        Vec::new()
                    } else {
                        vec![Certificate { encoded_certificate: view.cert_chain.to_vec() }]
                    },
                },
            })
        }
    }

    /// A struct of references to the various fields in a Response.
    pub struct BufferedResponse<'a> {
        /// The generated key.
        pub key_blob: &'a mut [u8],
        /// The certificate chain.
        pub cert_chain: &'a mut [u8],
    }

    impl<'a> TryFrom<&'a mut Response> for BufferedResponse<'a> {
        type Error = Error;
        fn try_from(response: &'a mut Response) -> Result<BufferedResponse<'a>, Self::Error> {
            // Peek into key blob to get size that follows in words.
            let key_blob_words = U32LE::ref_from_prefix(&response.suffix[0..size_of::<u32>()])
                .map_err(|_| km_err!(EncodingError, "word length"))?
                .0
                .get() as usize;
            let (key_blob, suffix) = response
                .suffix
                .split_at_mut_checked((key_blob_words + 1) * WORD_SIZE)
                .ok_or(km_err!(EncodingError, "split response"))?;
            let (cert_chain_bytes, suffix) = suffix
                .split_at_mut_checked(WORD_SIZE)
                .ok_or(km_err!(EncodingError, "split response"))?;
            let cert_chain_bytes = U32LE::ref_from_prefix(cert_chain_bytes)
                .map_err(|_| km_err!(EncodingError, "cert length"))?
                .0
                .get() as usize;
            if suffix.len() < cert_chain_bytes {
                return Err(km_err!(EncodingError, "cert underflow"));
            }
            Ok(BufferedResponse { key_blob, cert_chain: &mut suffix[0..cert_chain_bytes] })
        }
    }
}

/// Vendor TPM command representing a strongbox get dice chain request.
pub mod get_dice_chain {
    use super::*;

    /// This command has no inputs, so Request is an empty struct.
    #[derive(Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request;

    impl TpmvRequest for Request {
        const TAG: U16<BE> = NO_SESSION_TAG;
        const COMMAND_CODE: U16<BE> = U16::new(0xA0u16);
        const ORDINAL: U32<BE> = VENDOR_COMMAND_STRONGBOX;
        type TpmvResponse = Response;
    }

    /// Represents a response from a [`Request`]
    #[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// A dice chain.
        pub data: [u8],
    }
}

/// Vendor TPM command representing a strongbox get hardware info request.
pub mod get_hardware_info {
    use super::*;

    /// This command has no inputs, so Request is an empty struct.
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request;

    impl_tpmv_request!(GetHardwareInfoRequest);

    impl TpmvRequestBuild for Request {
        type BuildParams = kmr_wire::GetHardwareInfoRequest;

        type Err = Error;

        fn expected_size(_params: &Self::BuildParams) -> Result<u32, Self::Err> {
            Ok(0u32)
        }

        fn init(&mut self, _params: Self::BuildParams) -> Result<(), Self::Err> {
            Ok(())
        }
    }

    /// Represents a response from a [`Request`]
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// Stronbox version
        pub version: I32<BE>,
        /// Keymint security level (KM_SECURITY_STRONGBOX = 2)
        pub security_level: I32<BE>,
        /// Keymint name length (4)
        pub keymint_name_len: U32<BE>,
        /// Keymint name (CR50)
        pub keymint_name: [u8; 4],
        /// Keymint author length (6)
        pub keymint_author_len: U32<BE>,
        /// Keymint author (Google\0\0)
        pub keymint_author: [u8; 8],
        /// Timestamp token required (false)
        pub timestamp_token_required: U32<BE>,
    }

    impl<'a> TryFrom<&'a mut Response> for GetHardwareInfoResponse {
        type Error = Error;

        fn try_from(resp: &'a mut Response) -> Result<Self, Self::Error> {
            let name_len = resp.keymint_name_len.get() as usize;
            let author_len = resp.keymint_author_len.get() as usize;
            Ok(GetHardwareInfoResponse {
                ret: KeyMintHardwareInfo {
                    version_number: resp.version.get(),
                    security_level: SecurityLevel::try_from(resp.security_level.get())
                        .map_err(|_| km_err!(EncodingError, "security_level"))?,
                    key_mint_name: String::from_utf8(resp.keymint_name[..name_len].to_vec())
                        .map_err(|_| km_err!(EncodingError, "keymint_name"))?,
                    key_mint_author_name: String::from_utf8(
                        resp.keymint_author[..author_len].to_vec(),
                    )
                    .map_err(|_| km_err!(EncodingError, "keymint_author"))?,

                    timestamp_token_required: resp.timestamp_token_required.get() != 0,
                },
            })
        }
    }
}

/// Key purpose enum used in keymint operations.
#[derive(Debug, Eq, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
#[repr(C)]
pub struct KeyPurpose(I32<LE>);

impl KeyPurpose {
    /// Encrypt with the key.
    pub const ENCRYPT: Self = KeyPurpose(I32::new(keymint::KeyPurpose::Encrypt as i32));
    /// Decrypt with the key.
    pub const DECRYPT: Self = KeyPurpose(I32::new(keymint::KeyPurpose::Decrypt as i32));
    /// Sign with the key.
    pub const SIGN: Self = KeyPurpose(I32::new(keymint::KeyPurpose::Sign as i32));
    /// Verify with the key.
    pub const VERIFY: Self = KeyPurpose(I32::new(keymint::KeyPurpose::Verify as i32));
    /// Wrap a blob with the key.
    pub const WRAP_KEY: Self = KeyPurpose(I32::new(keymint::KeyPurpose::WrapKey as i32));
    /// Agree with the key.
    pub const AGREE_KEY: Self = KeyPurpose(I32::new(keymint::KeyPurpose::AgreeKey as i32));
    /// Attest with the key.
    pub const ATTEST_KEY: Self = KeyPurpose(I32::new(keymint::KeyPurpose::AttestKey as i32));
}

impl From<keymint::KeyPurpose> for KeyPurpose {
    fn from(value: keymint::KeyPurpose) -> Self {
        KeyPurpose(I32::new(value as i32))
    }
}

/// Keymint Device begin operation.
/// Input Buffer (`buf`):
/// - [ 4 bytes ] enum km_purpose: The purpose of the operation (e.g., SIGN).
/// - [ 4 bytes ] uint32_t key_blob_words: The size of the key blob that
///   follows, in 32-bit words.
/// - [ n bytes ] The key blob generated by `generateKey`.
/// - [ 4 bytes ] uint32_t additional_params_words: The size of the
///   additional parameters list that follows, in 32-bit words.
/// - [ m bytes ] Serialized KeyMint tags for additional parameters
///   (e.g., APPLICATION_ID).
///
/// Output Buffer (`buf`):
/// A BeginResult structure.
/// - [ 8 bytes ] uint64_t challenge: Currently unused, set to 0.
/// - [ 4 bytes ] uint32_t key_params_size_bytes: Size of KeyParameters that
///   follow. Currently 0.
/// - [ n bytes ] KeyParameters (e.g., IV). Currently empty.
/// - [ 4 bytes ] uint32_t operation_id: A unique handle for this operation.
pub mod begin {
    use super::*;

    /// The GSC equivalent of a kmr_wire::BeginRequest.
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request {
        /// The purpose of the operation (e.g., SIGN).
        pub purpose: KeyPurpose,
        /// The size of the key blob that follows in 32-bit words (included in the key blob).
        /// Trailing bytes
        ///   pub key_blob: [u8; N],
        ///   pub additional_parameters_words: U32LE,
        ///   pub additional_parameters: [u8; M],
        pub suffix: [u8],
    }

    impl_tpmv_request!(BeginRequest);

    impl TpmvRequestBuild for Request {
        type BuildParams = kmr_wire::BeginRequest;

        type Err = Error;

        fn expected_size(params: &Self::BuildParams) -> Result<u32, Self::Err> {
            let static_size = size_of::<KeyPurpose>() + size_of::<U32LE>();
            static_size
                .checked_add(params.key_blob.len())
                .ok_or(km_err!(EncodingError, ""))?
                .checked_add(key_param::expected_size(&params.params))
                .ok_or(km_err!(EncodingError, ""))?
                .try_into()
                .map_err(|_| km_err!(EncodingError, ""))
        }

        fn init(&mut self, params: Self::BuildParams) -> Result<(), Self::Err> {
            let additional_parameters_bytes = key_param::expected_size(&params.params);
            self.purpose = params.purpose.into();
            let view =
                BufferedRequest::new(self, params.key_blob.len(), additional_parameters_bytes)?;
            view.key_blob.copy_from_slice(&params.key_blob);
            *view.additional_parameters_words = U32LE::new(
                (additional_parameters_bytes / WORD_SIZE)
                    .try_into()
                    .map_err(|_| km_err!(EncodingError, ""))?,
            );
            let _ = key_param::serialize_key_params(view.additional_parameters, &params.params);
            Ok(())
        }
    }

    /// A struct of references to the various fields in a Request.
    pub struct BufferedRequest<'a> {
        /// The purpose of the operation (e.g., SIGN).
        pub purpose: &'a mut KeyPurpose,
        /// The key blob generated by `generateKey`.
        pub key_blob: &'a mut [u8],
        /// The size of the additional parameters list that follows, in 32-bit words.
        pub additional_parameters_words: &'a mut U32LE,
        /// Serialized KeyMint tags for additional parameters (e.g., APPLICATION_ID).
        pub additional_parameters: &'a mut [u8],
    }

    impl<'a> BufferedRequest<'a> {
        /// Construct a BufferedRequest with the provided parameters backed by request.
        pub fn new(
            request: &'a mut Request,
            key_blob_bytes: usize,
            additional_parameters_bytes: usize,
        ) -> Result<BufferedRequest<'a>, Error> {
            let (key_blob, suffix) = request
                .suffix
                .split_at_mut_checked(key_blob_bytes)
                .ok_or(km_err!(EncodingError, ""))?;
            let (additional_parameters, additional_parameters_words) = get_u32le(suffix)?;
            if additional_parameters_bytes != additional_parameters.len() {
                return Err(km_err!(EncodingError, ""));
            }

            Ok(BufferedRequest {
                purpose: &mut request.purpose,
                key_blob,
                additional_parameters_words,
                additional_parameters,
            })
        }
    }

    impl<'a> TryFrom<&'a mut Request> for BufferedRequest<'a> {
        type Error = Error;
        fn try_from(request: &'a mut Request) -> Result<BufferedRequest<'a>, Error> {
            let key_blob_words = U32LE::ref_from_prefix(&request.suffix[0..size_of::<u32>()])
                .map_err(|_| km_err!(EncodingError, "word length"))?
                .0
                .get() as usize;
            let (key_blob, suffix) = request
                .suffix
                .split_at_mut_checked(key_blob_words * size_of::<U32LE>())
                .ok_or(km_err!(EncodingError, ""))?;
            let (additional_parameters, additional_parameters_words) = get_u32le(suffix)?;
            if additional_parameters_words.get() as usize * size_of::<U32LE>()
                != additional_parameters.len()
            {
                return Err(km_err!(Unimplemented, ""));
            }

            Ok(BufferedRequest {
                purpose: &mut request.purpose,
                key_blob,
                additional_parameters_words,
                additional_parameters,
            })
        }
    }

    /// The GSC equivalent of a kmr_wire::BeginResponse.
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// Stronbox version
        pub challenge: I64LE,
        /// Size of key_parameters that follow.
        pub key_parameters_size_bytes: U32LE,
        /// Trailing bytes
        ///   pub key_parameters: [u8; N],
        ///   pub operation_id: U32LE,  // Unique handle for this operation.
        pub suffix: [u8],
    }

    impl TryFrom<&mut Response> for kmr_wire::BeginResponse {
        type Error = Error;

        /// Convert a response into a kmr_wire::BeginResponse.
        fn try_from(response: &mut Response) -> Result<kmr_wire::BeginResponse, Error> {
            let view = BufferedResponse::try_from(response)?;
            let params = key_param::parse_key_params(
                <[u32]>::ref_from_bytes(view.key_parameters)
                    .map_err(|_| km_err!(EncodingError, "key parameters"))?,
            )?;
            Ok(kmr_wire::BeginResponse {
                ret: kmr_wire::InternalBeginResult {
                    challenge: view.challenge.get(),
                    params,
                    op_handle: view.operation_id.get() as i64,
                },
            })
        }
    }

    /// A struct of references to the various fields in a Response.
    pub struct BufferedResponse<'a> {
        /// Currently unused, set to 0.
        pub challenge: &'a mut I64<LE>,
        /// Size of KeyParameters that follow. Currently 0.
        pub key_parameters_size_bytes: &'a mut U32LE,
        /// KeyParameters (e.g., IV). Currently empty.
        pub key_parameters: &'a mut [u8],
        /// A unique handle for this operation.
        pub operation_id: &'a mut U32LE,
    }

    impl<'a> TryFrom<&'a mut Response> for BufferedResponse<'a> {
        type Error = Error;
        fn try_from(response: &'a mut Response) -> Result<BufferedResponse<'a>, Self::Error> {
            let (key_parameters, suffix) = response
                .suffix
                .split_at_mut_checked(response.key_parameters_size_bytes.get() as usize)
                .ok_or(km_err!(Unimplemented, "Key parameters aren't supported yet"))?;
            let operation_id =
                U32LE::mut_from_bytes(suffix).map_err(|_| km_err!(InvalidOperationHandle, ""))?;

            Ok(BufferedResponse {
                challenge: &mut response.challenge,
                key_parameters_size_bytes: &mut response.key_parameters_size_bytes,
                key_parameters,
                operation_id,
            })
        }
    }
}

/// Keymint Update Operation.
/// Input Buffer (`buf`):
/// - [ 4 bytes ] uint32_t operation_id: The handle from `begin()`.
/// - [ 4 bytes ] uint32_t update_size_bytes: The size of the data to process.
/// - [ n bytes ] The input data to be added to the operation.
///
/// Output Buffer (`buf`):
/// - Empty. `*out_len_bytes` is set to 0.
pub mod update {
    use super::*;

    /// The GSC equivalent of kmr_wire::UpdateRequest
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request {
        /// A unique handle for this operation.
        pub operation_id: U32LE,
        /// The size of the key blob that follows in 32-bit words.
        pub update_size_bytes: U32LE,
        /// The data to process during the update operation.
        pub input_data: [u8],
    }

    impl_tpmv_request!(UpdateRequest);

    impl TpmvRequestBuild for Request {
        type BuildParams = kmr_wire::UpdateRequest;

        type Err = Error;

        fn expected_size(params: &Self::BuildParams) -> Result<u32, Self::Err> {
            let static_size = 2 * size_of::<U32LE>();
            let input_len = params.input.len().next_multiple_of(WORD_SIZE);
            if params.auth_token.is_some() {
                km_err!(Unimplemented, "UpdateRequest::auth_token");
            }
            if params.timestamp_token.is_some() {
                km_err!(Unimplemented, "UpdateRequest::timestamp_token");
            }
            static_size
                .checked_add(input_len)
                .ok_or(km_err!(EncodingError, ""))?
                .try_into()
                .map_err(|_| km_err!(EncodingError, ""))
        }

        fn init(&mut self, params: Self::BuildParams) -> Result<(), Self::Err> {
            self.operation_id =
                U32LE::new(params.op_handle.try_into().map_err(|_| km_err!(EncodingError, ""))?);
            self.update_size_bytes =
                U32LE::new(params.input.len().try_into().map_err(|_| km_err!(InvalidKeyBlob, ""))?);
            self.input_data[..params.input.len()].copy_from_slice(&params.input);
            self.input_data[params.input.len()..].fill(0);
            Ok(())
        }
    }

    /// The GSC equivalent of kmr_wire::UpdateResponse
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// Returned bytes.
        pub ret: [u8],
    }

    impl TryFrom<&mut Response> for kmr_wire::UpdateResponse {
        type Error = Error;

        /// Convert a response into a kmr_wire::UpdateResponse.
        fn try_from(response: &mut Response) -> Result<kmr_wire::UpdateResponse, Error> {
            Ok(kmr_wire::UpdateResponse { ret: response.ret.to_vec() })
        }
    }
}

/// Keymint Finish Operation.
/// Input Buffer (`buf`):
/// - [ 4 bytes ] uint32_t operation_id: The handle from `begin()`.
/// - [ 4 bytes ] uint32_t update_size_bytes: The size of the final data.
/// - [ n bytes ] The final input data for the operation. Can be empty.
///
/// Output Buffer (`buf`):
/// The result of the operation. Specifically for the Strongbox-subset it is:
/// - [ 64 bytes ] An ECDSA P-256 signature, composed of the 32-byte 'r'
///   value followed by the 32-byte 's' value.
pub mod finish {
    use super::*;

    /// The GSC equivalent of kmr_wire::UpdateRequest
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request {
        /// A unique handle for this operation.
        pub operation_id: U32LE,
        /// The size of the data that follows in bytes.
        pub update_size_bytes: U32LE,
        /// The data to process during the update operation.
        pub input_data: [u8],
    }

    impl_tpmv_request!(FinishRequest);

    impl TpmvRequestBuild for Request {
        type BuildParams = kmr_wire::FinishRequest;

        type Err = Error;

        fn expected_size(params: &Self::BuildParams) -> Result<u32, Self::Err> {
            let static_size = 2 * size_of::<U32LE>();
            let input_len = match params.input.as_ref() {
                Some(input) => input.len().next_multiple_of(WORD_SIZE),
                None => 0,
            };
            if params.signature.is_some() {
                km_err!(Unimplemented, "FinishRequest::signature");
            }
            if params.auth_token.is_some() {
                km_err!(Unimplemented, "FinishRequest::auth_token");
            }
            if params.timestamp_token.is_some() {
                km_err!(Unimplemented, "FinishRequest::timestamp_token");
            }
            if params.confirmation_token.is_some() {
                km_err!(Unimplemented, "FinishRequest::confirmation_token");
            }
            static_size
                .checked_add(input_len)
                .ok_or(km_err!(EncodingError, ""))?
                .try_into()
                .map_err(|_| km_err!(EncodingError, ""))
        }

        fn init(&mut self, params: Self::BuildParams) -> Result<(), Self::Err> {
            self.operation_id =
                U32LE::new(params.op_handle.try_into().map_err(|_| km_err!(EncodingError, ""))?);
            if let Some(input) = params.input.as_ref() {
                self.input_data[..input.len()].copy_from_slice(input);
                self.input_data[input.len()..].fill(0);
                self.update_size_bytes =
                    U32LE::new(input.len().try_into().map_err(|_| km_err!(InvalidKeyBlob, ""))?);
            } else {
                self.update_size_bytes = U32LE::ZERO;
            }
            Ok(())
        }
    }

    /// The GSC equivalent of kmr_wire::FinishResponse
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// Returned bytes.
        pub ret: [u8],
    }

    impl TryFrom<&mut Response> for kmr_wire::FinishResponse {
        type Error = Error;

        /// Convert a response into a kmr_wire::FinishResponse.
        fn try_from(response: &mut Response) -> Result<kmr_wire::FinishResponse, Error> {
            if response.ret.len() != 64 {
                return Err(km_err!(EncodingError, "unexpected signature size"));
            }
            let r = BigNum::from_slice(&response.ret[0..32])
                .map_err(|_| km_err!(EncodingError, "bignum"))?;
            let s = BigNum::from_slice(&response.ret[32..])
                .map_err(|_| km_err!(EncodingError, "bignum"))?;
            let ret = EcdsaSig::from_private_components(r, s)
                .map_err(|_| km_err!(EncodingError, "from components"))?
                .to_der()
                .map_err(|_| km_err!(EncodingError, "to der"))?;
            Ok(kmr_wire::FinishResponse { ret })
        }
    }
}

/// Keymint Abort Operation - Cr50 doesn't have abort use use finish instead.
/// Input Buffer (`buf`):
/// - [ 4 bytes ] uint32_t operation_id: The handle from `begin()`.
/// - [ 4 bytes ] uint32_t update_size_bytes: Always 0.
///
/// Output Buffer (`buf`):
/// The result of the operation. Specifically for the Strongbox-subset it is:
/// - [ 64 bytes ] An ECDSA P-256 signature, composed of the 32-byte 'r'
///   value followed by the 32-byte 's' value - We drop this.
pub mod abort {
    use super::*;

    /// The GSC equivalent of kmr_wire::UpdateRequest
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request {
        /// A unique handle for this operation.
        pub operation_id: U32LE,
        /// The size of the data that follows in bytes---Always 0.
        pub update_size_bytes: U32LE,
    }

    impl_tpmv_request!(FinishRequest);

    impl TpmvRequestBuild for Request {
        type BuildParams = kmr_wire::AbortRequest;

        type Err = Error;

        fn expected_size(_params: &Self::BuildParams) -> Result<u32, Self::Err> {
            Ok((2 * size_of::<U32LE>()) as u32)
        }

        fn init(&mut self, params: Self::BuildParams) -> Result<(), Self::Err> {
            self.operation_id =
                U32LE::new(params.op_handle.try_into().map_err(|_| km_err!(EncodingError, ""))?);
            self.update_size_bytes = U32LE::ZERO;
            Ok(())
        }
    }

    /// The GSC equivalent of kmr_wire::FinishResponse
    #[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// Returned bytes.
        pub ret: [u8],
    }

    impl TryFrom<&mut Response> for kmr_wire::AbortResponse {
        type Error = Error;

        /// Convert a response into a kmr_wire::FinishResponse.
        fn try_from(_response: &mut Response) -> Result<kmr_wire::AbortResponse, Error> {
            Ok(kmr_wire::AbortResponse {})
        }
    }
}
