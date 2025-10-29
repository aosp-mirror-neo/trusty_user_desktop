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
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, BE, U16, U32};

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
