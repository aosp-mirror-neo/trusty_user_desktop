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

use crate::{TpmvRequest, NO_SESSION_TAG};
use kmr_wire::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, BE, I32, U16, U32};

/// The ordinal value that is used for all strongbox commands
const VENDOR_COMMAND_STRONGBOX: U32<BE> = U32::new(0x20000001);

/// Vendor TPM command representing a strongbox generate ecdsa P256 keypair request.
pub mod generate_ecdsa_p256_keypair {
    use super::*;

    /// This command has no inputs, so Request is an empty struct.
    #[derive(Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request;

    impl TpmvRequest for Request {
        const TAG: U16<BE> = NO_SESSION_TAG;
        const COMMAND_CODE: U16<BE> = U16::new(GenerateEcdsaP256KeyPairRequest::CODE as u16);
        const ORDINAL: U32<BE> = VENDOR_COMMAND_STRONGBOX;
        type TpmvResponse = Response;
    }

    /// Represents a response from a [`Request`]
    #[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// A public key. The TA may treat this as opaque data to later be passed back to the GSC.
        pub data: [u8],
    }
}

/// Vendor TPM command representing a strongbox get hardware info request.
pub mod get_hardware_info {
    use super::*;

    /// This command has no inputs, so Request is an empty struct.
    #[derive(Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request;

    impl TpmvRequest for Request {
        const TAG: U16<BE> = NO_SESSION_TAG;
        const COMMAND_CODE: U16<BE> = U16::new(GetHardwareInfoRequest::CODE as u16);
        const ORDINAL: U32<BE> = VENDOR_COMMAND_STRONGBOX;
        type TpmvResponse = Response;
    }

    /// Represents a response from a [`Request`]
    #[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// Stronbox version
        pub version: I32<BE>,
        /// Keymint security level (KM_SECURITY_STRONGBOX = 2)
        pub security_level: U32<BE>,
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
        /// TODO: remove when firmware removes the extra bytes
        pub unused: [u8; 7],
    }
}
