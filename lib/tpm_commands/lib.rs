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

use zerocopy::{
    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, BE, U16, U32,
};

/// Indicates that the request will run without a session. All TPM vendor
/// commands use this tag
const NO_SESSION_TAG: U16<BE> = U16::new(0x8001);

/// The ordinal value that is used for all vendor commands
const VENDOR_COMMAND_ORDINAL: U32<BE> = U32::new(0x20000000);

/// The ordinal value that is used for all extension commands
const EXTENSION_COMMAND_ORDINAL: U32<BE> = U32::new(0xBACCD00A);

/// A `u32` that is always equal to zero
#[derive(
    Clone, Copy, Debug, Default, Eq, FromZeros, IntoBytes, Immutable, KnownLayout, PartialEq,
)]
#[repr(u32)]
pub enum AlignedZeroU32 {
    /// The sole enum
    #[default]
    Zero = 0,
}

/// An unaligned wrapper around [`AlignedZeroU32`]
/// TODO: https://github.com/google/zerocopy/issues/2273 - Replace with zerocopy implementation
#[repr(C, packed)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    FromZeros,
    IntoBytes,
    Immutable,
    KnownLayout,
    PartialEq,
    Unaligned,
)]
pub struct ZeroU32(AlignedZeroU32);

/// Possible return values from a [`get_version_info::Request`]
#[derive(
    Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Unaligned,
)]
#[repr(C)]
// TODO: https://github.com/kupiakos/open-enum/issues/27 - use open_enum when it supports U32<BE>
pub struct UpdateStatus(pub U32<BE>);

impl UpdateStatus {
    #![allow(nonstandard_style, dead_code, missing_docs)]
    pub const Success: Self = UpdateStatus(U32::new(0));
    pub const BadAddr: Self = UpdateStatus(U32::new(1));
    pub const EraseFailure: Self = UpdateStatus(U32::new(2));
    pub const DataError: Self = UpdateStatus(U32::new(3));
    pub const WriteFailure: Self = UpdateStatus(U32::new(4));
    pub const VerifyError: Self = UpdateStatus(U32::new(5));
    pub const GenError: Self = UpdateStatus(U32::new(6));
    pub const NoMemError: Self = UpdateStatus(U32::new(7));
    pub const RollbackError: Self = UpdateStatus(U32::new(8));
    pub const RateLimitError: Self = UpdateStatus(U32::new(9));
    pub const UnalignedBlockError: Self = UpdateStatus(U32::new(10));
    pub const TruncatedHeaderError: Self = UpdateStatus(U32::new(11));
    pub const BoardIdError: Self = UpdateStatus(U32::new(12));
    pub const BoardFlagsError: Self = UpdateStatus(U32::new(13));
    pub const DevIdMismatch: Self = UpdateStatus(U32::new(14));
}

/// A trait used to define the constants required by each type of TPMV request
/// All TPMV requests are required to implement this trait
pub trait TpmvRequest: IntoBytes + Immutable + Unaligned + Sized {
    /// The first 4 bytes of every TPM request and response.
    /// Used to indicate if the request requires a session to be run
    const TAG: U16<BE>;

    /// A code that is unique to each request type that the TPM will recognize
    /// and know how to process
    const COMMAND_CODE: U16<BE>;

    /// The ordinal associated with the request type.
    const ORDINAL: U32<BE>;

    /// Each request type has an associated response type used to deserialize
    /// bytes received from the TPM after a request is processed
    type TpmvResponse: FromBytes + ?Sized + Unaligned;
}

/// Represents a complete TPM request. Contains both the request header and any
/// additional fields required by the request type
#[derive(Debug, Eq, IntoBytes, Immutable, PartialEq)]
#[repr(C)]
pub struct TpmRequestMessage<T: TpmvRequest> {
    /// The request header
    header: TpmRequestHeader,

    /// Contains fields specific to the type of request being sent
    pub request: T,
}

impl<T: TpmvRequest> TpmRequestMessage<T> {
    /// Generates a new `TpmvRequest` of the provided type T
    pub fn new(request: T) -> Self {
        Self {
            header: TpmRequestHeader {
                tag: T::TAG,
                length: U32::new(size_of::<Self>() as u32),
                ordinal: T::ORDINAL,
                command_code: T::COMMAND_CODE,
            },
            request,
        }
    }
}

/// Represents the initial bytes of every TPM request.
#[derive(Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
#[repr(C)]
pub struct TpmRequestHeader {
    /// The first 4 bytes of every TPM request
    pub tag: U16<BE>,

    /// The total number of bytes in the request
    pub length: U32<BE>,

    /// The request's ordinal
    pub ordinal: U32<BE>,

    /// A code that is unique to each request type that the TPM will recognize
    /// and know how to process
    pub command_code: U16<BE>,
}

/// Represents a complete TPM response. Contains both the response header and any
/// additional fields required by the response type
#[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq)]
#[repr(C)]
pub struct TpmResponseMessage<T: ?Sized> {
    /// The response header
    pub header: TpmResponseHeader,

    /// Contains fields specific to the type of response being sent
    pub response: T,
}

/// Represents the initial bytes of every TPM response.
#[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq)]
#[repr(C)]
pub struct TpmResponseHeader {
    /// The first 4 bytes of every TPM response
    /// Used to indicate if the request requires a session to be run
    pub tag: U16<BE>,

    /// The total number of bytes in the response
    pub length: U32<BE>,

    /// Used to indicate if an error occurred while processing the request
    pub error_code: U32<BE>,

    /// The same command code present in the initial request
    pub command_code: U16<BE>,
}

/// A module containing the requests and responses used to retrieve console
/// logs from ths GSC
pub mod get_console_log {
    use super::*;
    /// Used to retrieve the oldest (2048 - header size) bytes worth of console logs from the device.
    /// Repeated calls can be used to consume all previously unread console logs.
    /// Returns an empty string when there are no more logs to read
    #[derive(Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request;

    impl TpmvRequest for Request {
        const TAG: U16<BE> = NO_SESSION_TAG;
        const COMMAND_CODE: U16<BE> = U16::new(0x0043);
        const ORDINAL: U32<BE> = VENDOR_COMMAND_ORDINAL;
        type TpmvResponse = Response;
    }

    /// Represents a response from a [`Request`]
    #[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// A dynamically sized slice containing ASCII characters
        pub data: [u8],
    }
}

/// A module containing the requests and responses used to retrieve version
/// info from ths GSC
pub mod get_version_info {
    use super::*;
    /// Requests version info from the device
    #[derive(Default, IntoBytes, Immutable, Unaligned)]
    #[repr(C)]
    pub struct Request {
        /// The block digest. Always equal to zero when getting version info
        pub digest: ZeroU32,
        /// The destination address. Always equal to zero when getting version info
        pub address: ZeroU32,
    }

    impl TpmvRequest for Request {
        const TAG: U16<BE> = NO_SESSION_TAG;
        const COMMAND_CODE: U16<BE> = U16::new(0x0004);
        const ORDINAL: U32<BE> = EXTENSION_COMMAND_ORDINAL;
        type TpmvResponse = Response;
    }

    /// Represents a response from a [`Request`]
    /// TODO: b/394187914 - Add support for older protocols
    #[derive(Debug, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// Indicates what error (if any) occurred while fetching version info
        pub return_value: UpdateStatus,
        /// The update protocol currently being used by the GSC. Mostly used to
        /// indicate which fields will be present in the response
        pub protocol_version: U32<BE>,
        /// The offset at which the RO section of the GSC image begins
        pub backup_ro_offset: U32<BE>,
        /// The offset at which the RW section of the GSC image begins
        pub backup_rw_offset: U32<BE>,
        /// The RO minor version
        pub ro_minor: U32<BE>,
        /// The RO major version
        pub ro_major: U32<BE>,
        /// The RO epoch
        pub ro_epoch: U32<BE>,
        /// The RW minor version
        pub rw_minor: U32<BE>,
        /// The RW major version
        pub rw_major: U32<BE>,
        /// The RW epoch
        pub rw_epoch: U32<BE>,
        /// The key id of the currently active RO section
        pub ro_keyid: U32<BE>,
        /// The key id of the currently active RW section
        pub rw_keyid: U32<BE>,
    }
}

/// Contains the requests and responses used to access superblock mac
/// storage on the GSC.
pub mod trusty_storage_superblock_mac {
    use super::*;

    /// Trusty storage application mac.
    #[derive(
        Clone,
        Copy,
        Debug,
        Default,
        Eq,
        FromBytes,
        IntoBytes,
        Immutable,
        KnownLayout,
        PartialEq,
        Unaligned,
    )]
    #[repr(C)]
    pub struct TrustyStorageMac(pub [u8; 16]);

    /// Supported storage mac commands.
    #[derive(Clone, Copy, Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
    #[repr(u8)]
    pub enum TrustyStorageMacCommand {
        /// Read operation.
        Read = 0,
        /// Write operation.
        Write = 1,
    }

    /// Used by the Trusty secure storage application to store the MAC of the
    /// current valid superblock.
    #[derive(Clone, Copy, Debug, Eq, IntoBytes, Immutable, PartialEq, TryFromBytes, Unaligned)]
    #[repr(u8)]
    pub enum TrustyStorageMacFileIndex {
        /// Tamper detect persist filesystem mac index.
        TamperDetectPersist = 1,
        /// Tamper detect filesystem mac index.
        TamperDetect = 2,
    }

    /// Requests superblock mac reads/writes from the GSC.
    #[derive(Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Request {
        /// Operation to perform.
        pub command: TrustyStorageMacCommand,
        /// File identifier.
        pub index: TrustyStorageMacFileIndex,
        /// MAC data to write.
        pub mac: TrustyStorageMac,
    }

    impl Request {
        /// Create a new read request.
        pub fn new_read(index: TrustyStorageMacFileIndex) -> Self {
            Self { command: TrustyStorageMacCommand::Read, index, mac: TrustyStorageMac::default() }
        }

        /// Create a new write request.
        pub fn new_write(index: TrustyStorageMacFileIndex, mac: TrustyStorageMac) -> Self {
            Self { command: TrustyStorageMacCommand::Write, index, mac }
        }
    }

    impl TpmvRequest for Request {
        const TAG: U16<BE> = NO_SESSION_TAG;
        const COMMAND_CODE: U16<BE> = U16::new(0x004D);
        const ORDINAL: U32<BE> = VENDOR_COMMAND_ORDINAL;
        type TpmvResponse = Response;
    }

    /// Represents a response from a [`Request`]
    #[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
    #[repr(C)]
    pub struct Response {
        /// Data currently stored.
        pub mac: TrustyStorageMac,
    }
}

#[cfg(test)]
mod tests {
    use super::get_console_log;
    use super::get_version_info;
    use super::*;

    #[test]
    fn test_get_console_logs_serialize() {
        let request = TpmRequestMessage::new(get_console_log::Request {});
        let expected_bytes = vec![
            0x80, 0x01, // header.tag
            0x00, 0x00, 0x00, 0x0C, // header.length
            0x20, 0x00, 0x00, 0x00, // header.ordinal
            0x00, 0x43, // header.subcmd
        ];

        assert_eq!(expected_bytes, request.as_bytes());
    }

    #[test]
    fn test_get_console_logs_deserialize() {
        let bytes = vec![
            0x80, 0x01, // header.tag
            0x00, 0x00, 0x00, 0x24, // header.length
            0xDE, 0xAD, 0xBE, 0xEF, // header.error_code
            0x00, 0x43, // header.subcmd
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, // data
        ];

        let tpm_response =
            TpmResponseMessage::<get_console_log::Response>::ref_from_bytes(&bytes).unwrap();
        assert_eq!(
            String::from("Hello!"),
            String::from_utf8(Vec::from(&tpm_response.response.data)).unwrap(),
        );
    }

    #[test]
    fn test_version_info_serialize() {
        let request = TpmRequestMessage::<get_version_info::Request>::new(Default::default());
        let expected_bytes = vec![
            0x80, 0x01, // header.tag
            0x00, 0x00, 0x00, 0x14, // header.length
            0xBA, 0xCC, 0xD0, 0x0A, // header.ordinal
            0x00, 0x04, // header.subcmd
            0x00, 0x00, 0x00, 0x00, // response.digest
            0x00, 0x00, 0x00, 0x00, // response.address
        ];

        assert_eq!(expected_bytes, request.as_bytes());
    }

    #[test]
    fn test_version_info_deserialize() {
        let bytes = vec![
            0x80, 0x01, // header.tag
            0x00, 0x00, 0x00, 0x3C, // header.length
            0xDE, 0xAD, 0xBE, 0xEF, // header.error_code
            0x00, 0x04, // header.subcmd
            0x00, 0x00, 0x00, 0x01, // response.return_value
            0x00, 0x00, 0x00, 0x06, // response.protocol_version
            0x00, 0x00, 0x00, 0xAA, // response.backup_ro_offset
            0x00, 0x00, 0x00, 0xBB, // response.backup_rw_offset
            0x00, 0x00, 0x00, 0x11, // response.ro_minor
            0x00, 0x00, 0x00, 0x22, // response.ro_major
            0x00, 0x00, 0x00, 0x33, // response.ro_epoch
            0x00, 0x00, 0x00, 0x44, // response.rw_minor
            0x00, 0x00, 0x00, 0x55, // response.rw_major
            0x00, 0x00, 0x00, 0x66, // response.rw_epoch
            0x00, 0x00, 0x00, 0xCC, // response.ro_keyid
            0x00, 0x00, 0x00, 0xDD, // response.rw_keyid
        ];

        let expected_response = TpmResponseMessage {
            header: TpmResponseHeader {
                tag: U16::new(0x8001),
                length: U32::new(0x0000003C),
                error_code: U32::new(0xDEADBEEF),
                command_code: U16::new(0x0004),
            },

            response: get_version_info::Response {
                return_value: UpdateStatus::BadAddr,
                protocol_version: U32::new(0x00000006),
                backup_ro_offset: U32::new(0x000000AA),
                backup_rw_offset: U32::new(0x000000BB),
                ro_minor: U32::new(0x00000011),
                ro_major: U32::new(0x00000022),
                ro_epoch: U32::new(0x00000033),
                rw_minor: U32::new(0x00000044),
                rw_major: U32::new(0x00000055),
                rw_epoch: U32::new(0x00000066),
                ro_keyid: U32::new(0x000000CC),
                rw_keyid: U32::new(0x000000DD),
            },
        };

        let tpm_response =
            TpmResponseMessage::<get_version_info::Response>::ref_from_bytes(&bytes).unwrap();
        assert_eq!(*tpm_response, expected_response);
    }

    #[test]
    fn test_trusty_storage_superblock_mac_serialize() {
        use trusty_storage_superblock_mac::{Request, TrustyStorageMacFileIndex};
        let index = TrustyStorageMacFileIndex::TamperDetectPersist;
        let request = TpmRequestMessage::<Request>::new(Request::new_read(index));
        let expected_bytes = vec![
            0x80, 0x01, // header.tag
            0x00, 0x00, 0x00, 0x1E, // header.length
            0x20, 0x00, 0x00, 0x00, // header.ordinal
            0x00, 0x4D, // header.subcmd
            0x00, // request.command
            0x01, // request.index
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // request.mac
        ];

        assert_eq!(expected_bytes, request.as_bytes());
    }

    #[test]
    fn test_trusty_storage_superblock_mac_deserialize() {
        use trusty_storage_superblock_mac::{Response, TrustyStorageMac};
        let bytes = vec![
            0x80, 0x01, // header.tag
            0x00, 0x00, 0x00, 0x1C, // header.length
            0xDE, 0xAD, 0xBE, 0xEF, // header.error_code
            0x00, 0x4D, // header.subcmd
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, // request.mac
        ];

        let expected_response = TpmResponseMessage {
            header: TpmResponseHeader {
                tag: U16::new(0x8001),
                length: U32::new(0x0000001C),
                error_code: U32::new(0xDEADBEEF),
                command_code: U16::new(0x004D),
            },

            response: Response { mac: TrustyStorageMac([2u8; 16]) },
        };

        let tpm_response = TpmResponseMessage::<Response>::ref_from_bytes(&bytes).unwrap();
        assert_eq!(*tpm_response, expected_response);
    }
}
