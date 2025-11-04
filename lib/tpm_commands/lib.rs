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
    ConvertError, FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, TryFromBytes,
    TryReadError, Unaligned, BE, U16, U32,
};

/// Indicates that the request will run without a session. All TPM vendor
/// commands use this tag
const NO_SESSION_TAG: U16<BE> = U16::new(0x8001);

/// The ordinal value that is used for all vendor commands
const VENDOR_COMMAND_ORDINAL: U32<BE> = U32::new(0x20000000);

/// The ordinal value that is used for all extension commands
const EXTENSION_COMMAND_ORDINAL: U32<BE> = U32::new(0xBACCD00A);

//pub(crate) const MAX_PAYLOAD_SIZE: usize = 2048 - core::mem::size_of::<TpmRequestHeader>();

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
/// TODO: <https://github.com/google/zerocopy/issues/2273> - Replace with zerocopy implementation
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
// TODO: <https://github.com/kupiakos/open-enum/issues/27> - use open_enum when it supports U32<BE>
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

/// Abstract the interface to the TPM/GSC so submodules can implement RPCs.
pub trait TpmInterface {
    /// An abstraction of the Error type returned by TPM RPCs.
    type Error;

    /// Transmit a TPM request message and get back a TPM response message.
    fn transmit<Req: TpmvRequest, Rsp: FromBytes + KnownLayout + Immutable>(
        &self,
        request: Req,
    ) -> Result<Rsp, Self::Error>;

    /// Transmit a TPM request message and get back a TPM response message.
    fn transmit_into<
        'a,
        Req: TpmvRequestBuild + ?Sized,
        Rsp: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned + ?Sized,
    >(
        &self,
        request: &TpmRequestMessage<Req>,
        buffer: &'a mut Vec<u8>,
    ) -> Result<&'a mut Rsp, Self::Error>;
}

/// Defines the constants required by each type of TPM vendor request.
///
/// All TPMV requests are required to implement this trait.
pub trait TpmvRequest: IntoBytes + Immutable + Unaligned {
    /// The first 4 bytes of every TPM request and response.
    /// Used to indicate if the request requires a session to be run
    const TAG: U16<BE>;

    /// A code that is unique to each request type that the TPM will recognize
    /// and know how to process
    const COMMAND_CODE: U16<BE>;

    /// The ordinal associated with the request type.
    const ORDINAL: U32<BE>;

    /// Each request type has an associated response type used to deserialize
    /// bytes received from the TPM after a request is processed.
    type TpmvResponse: TryFromBytes + ?Sized + Unaligned;
}

/// Operations to build a dynamically-sized request type.
///
/// See [`TpmRequestMessage::new_in_vec`].
pub trait TpmvRequestBuild: TpmvRequest + FromZeros + IntoBytes + KnownLayout {
    /// Parameters to build an self-consistent instance of this request from zeros.
    ///
    /// This does not need to fill every field of the request, only those that should
    /// be static for every instance of this message.
    type BuildParams;

    /// Error in initialization or size calculation.
    type Err;

    /// The expected size for the request in bytes, excluding the TPM header.
    ///
    /// If `Self: Sized` this should be `size_of::<Self>()`.
    fn expected_size(params: &Self::BuildParams) -> Result<u32, Self::Err>;

    /// Initializes a zeroed `self` to an internally consistent state.
    ///
    /// This is where data length fields should be initialized, for example.
    fn init(&mut self, params: Self::BuildParams) -> Result<(), Self::Err>;
}

/// Represents a complete TPM request. Contains both the request header and any
/// additional fields required by the request type
#[derive(Debug, Eq, TryFromBytes, IntoBytes, Immutable, PartialEq, KnownLayout, Unaligned)]
#[repr(C)]
pub struct TpmRequestMessage<T: TpmvRequest + ?Sized> {
    /// The request header
    header: TpmRequestHeader,

    /// Contains fields specific to the type of request being sent
    pub request: T,
}

impl<T: TpmvRequest> TpmRequestMessage<T> {
    /// Generates a new `TpmvRequest` for the provided type `T`.
    pub fn new(request: T) -> Self {
        Self { header: TpmRequestHeader::for_request::<T>(), request }
    }
}

/// An error while building a TPM Request from a buffer.
#[derive(thiserror::Error)]
pub enum TpmRequestBuildError<Req: ?Sized + TpmvRequestBuild> {
    /// Failed to allocate enough space for the request.
    #[error("failed to allocate enough space for the request")]
    Alloc,

    /// The size returned by the request was invalid.
    #[error("the request code gave an invalid size")]
    Size,

    /// `init` or `expected_size` in [`TpmvRequestBuild`] failed.
    #[error("internal request build error: {0}")]
    Internal(Req::Err),
}

impl<Req: ?Sized + TpmvRequestBuild> std::fmt::Debug for TpmRequestBuildError<Req>
where
    Req::Err: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alloc => write!(f, "Alloc"),
            Self::Size => write!(f, "Size"),
            Self::Internal(arg0) => f.debug_tuple("Internal").field(arg0).finish(),
        }
    }
}

impl<Req: ?Sized + TpmvRequestBuild> From<std::collections::TryReserveError>
    for TpmRequestBuildError<Req>
{
    fn from(_: std::collections::TryReserveError) -> Self {
        Self::Alloc
    }
}

impl<T: ?Sized + TpmvRequestBuild> TpmRequestMessage<T> {
    /// Builds a request message using the given `Vec` as backing memory.
    pub fn new_in_vec(
        buf: &mut Vec<u8>,
        params: <T as TpmvRequestBuild>::BuildParams,
    ) -> Result<&mut Self, TpmRequestBuildError<T>> {
        let data_size: usize = T::expected_size(&params)
            .map_err(TpmRequestBuildError::Internal)?
            .try_into()
            .map_err(|_| TpmRequestBuildError::Size)?;
        let total_size = data_size
            .checked_add(size_of::<TpmRequestHeader>())
            .ok_or(TpmRequestBuildError::Size)?;
        let total_size_u32: u32 = total_size.try_into().map_err(|_| TpmRequestBuildError::Size)?;
        if let Some(additional) = total_size.checked_sub(buf.len()) {
            buf.try_reserve(additional)?;
        }
        buf.clear();
        buf.resize(total_size, 0);
        let out = match Self::try_mut_from_bytes(&mut buf[..]).map_err(TryReadError::from) {
            Ok(m) if size_of_val(m) == total_size => Ok(m),
            Ok(_) | Err(ConvertError::Size(_)) => Err(TpmRequestBuildError::Size),
            Err(ConvertError::Validity(_)) => unreachable!("T: FromZeros"),
        }?;
        out.header = TpmRequestHeader::for_request_with_total_size::<T>(total_size_u32);
        out.request.init(params).map_err(TpmRequestBuildError::Internal)?;
        Ok(out)
    }
}

/// Represents the initial bytes of every TPM request.
#[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, PartialEq, Unaligned)]
#[repr(C)]
pub struct TpmRequestHeader {
    /// The first 4 bytes of every TPM request
    pub tag: U16<BE>,

    /// The total number of bytes in the request
    ///
    /// Rust usually calls this term a "size" - `[u32; 3]` has a size of 12, but a length of 3.
    pub length: U32<BE>,

    /// The request's ordinal
    pub ordinal: U32<BE>,

    /// A code that is unique to each request type that the TPM will recognize
    /// and know how to process
    pub command_code: U16<BE>,
}

impl TpmRequestHeader {
    /// Constructs a `TpmRequestHeader` for the given request and total message size in bytes.
    pub fn for_request_with_total_size<T: TpmvRequest + ?Sized>(size: u32) -> Self {
        TpmRequestHeader {
            tag: T::TAG,
            length: U32::new(size),
            ordinal: T::ORDINAL,
            command_code: T::COMMAND_CODE,
        }
    }

    /// Constructs a `TpmRequestHeader` for the given fixed-size request.
    pub fn for_request<T: TpmvRequest>() -> Self {
        const { assert!(size_of::<TpmRequestMessage<T>>() as u64 <= u32::MAX as u64) }
        Self::for_request_with_total_size::<T>(size_of::<TpmRequestMessage<T>>() as u32)
    }
}

/// Represents a complete TPM response. Contains both the response header and any
/// additional fields required by the response type
#[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, PartialEq)]
#[repr(C)]
pub struct TpmResponseMessage<T: ?Sized> {
    /// The response header
    pub header: TpmResponseHeader,

    /// Contains fields specific to the type of response being sent
    pub response: T,
}

/// Represents the initial bytes of every TPM response.
#[derive(Debug, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, PartialEq)]
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

pub mod pinweaver;

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

    /// Trusty storage application flags.
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
    pub struct TrustyStorageFlags(pub u8);

    /// Supported storage mac commands.
    #[derive(Clone, Copy, Debug, Eq, IntoBytes, Immutable, PartialEq, Unaligned)]
    #[repr(u8)]
    pub enum TrustyStorageMacCommand {
        /// Read operation.
        Read = 0,
        /// Write operation.
        Write = 1,
        /// Delete operation.
        Delete = 2,
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

    /// Trusty storage application data.
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
    pub struct TrustyStorageMacData {
        /// MAC data currently stored.
        pub mac: TrustyStorageMac,
        /// Super block flags.
        pub flags: TrustyStorageFlags,
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
        pub data: TrustyStorageMacData,
    }

    impl Request {
        /// Create a new read request.
        pub fn new_read(index: TrustyStorageMacFileIndex) -> Self {
            Self {
                command: TrustyStorageMacCommand::Read,
                index,
                data: TrustyStorageMacData::default(),
            }
        }

        /// Create a new write request.
        pub fn new_write(index: TrustyStorageMacFileIndex, data: TrustyStorageMacData) -> Self {
            Self { command: TrustyStorageMacCommand::Write, index, data }
        }

        /// Create a new delete request.
        pub fn new_delete(index: TrustyStorageMacFileIndex) -> Self {
            Self {
                command: TrustyStorageMacCommand::Delete,
                index,
                data: TrustyStorageMacData::default(),
            }
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
        /// MAC data currently stored.
        pub data: TrustyStorageMacData,
    }
}

pub mod strongbox;

#[cfg(test)]
mod tests {
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
        use trusty_storage_superblock_mac::{
            Request, TrustyStorageFlags, TrustyStorageMac, TrustyStorageMacData,
            TrustyStorageMacFileIndex,
        };
        let index = TrustyStorageMacFileIndex::TamperDetectPersist;
        let request = TpmRequestMessage::<Request>::new(Request::new_read(index));
        let expected_bytes = vec![
            0x80, 0x01, // header.tag
            0x00, 0x00, 0x00, 0x1F, // header.length
            0x20, 0x00, 0x00, 0x00, // header.ordinal
            0x00, 0x4D, // header.subcmd
            0x00, // request.command
            0x01, // request.index
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // request.data.mac
            0x00, // request.data.flags
        ];

        assert_eq!(expected_bytes, request.as_bytes());

        let index = TrustyStorageMacFileIndex::TamperDetect;
        let data = TrustyStorageMacData {
            mac: TrustyStorageMac([
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xff,
            ]),
            flags: TrustyStorageFlags(0x81),
        };
        let request = TpmRequestMessage::<Request>::new(Request::new_write(index, data));
        let expected_bytes = vec![
            0x80, 0x01, // header.tag
            0x00, 0x00, 0x00, 0x1F, // header.length
            0x20, 0x00, 0x00, 0x00, // header.ordinal
            0x00, 0x4D, // header.subcmd
            0x01, // request.command
            0x02, // request.index
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xff, // request.data.mac
            0x81, // request.data.flags
        ];

        assert_eq!(expected_bytes, request.as_bytes());
    }

    #[test]
    fn test_trusty_storage_superblock_mac_deserialize() {
        use trusty_storage_superblock_mac::{
            Response, TrustyStorageFlags, TrustyStorageMac, TrustyStorageMacData,
        };
        let bytes = vec![
            0x80, 0x01, // header.tag
            0x00, 0x00, 0x00, 0x1D, // header.length
            0xDE, 0xAD, 0xBE, 0xEF, // header.error_code
            0x00, 0x4D, // header.subcmd
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, // response.data.mac
            0x81, // response.data.flags
        ];

        let expected_response = TpmResponseMessage {
            header: TpmResponseHeader {
                tag: U16::new(0x8001),
                length: U32::new(0x0000001D),
                error_code: U32::new(0xDEADBEEF),
                command_code: U16::new(0x004D),
            },

            response: Response {
                data: TrustyStorageMacData {
                    mac: TrustyStorageMac([2u8; 16]),
                    flags: TrustyStorageFlags(0x81),
                },
            },
        };

        let tpm_response = TpmResponseMessage::<Response>::ref_from_bytes(&bytes).unwrap();
        assert_eq!(*tpm_response, expected_response);
    }

    #[test]
    fn test_request_new_in_vec() {
        #[derive(FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
        #[repr(C, packed)]
        struct FakeRequest {
            rest_len: U32<BE>,
            must_be_zero: [ZeroU32; 3],
            rest: [u8],
        }
        impl TpmvRequest for FakeRequest {
            const TAG: U16<BE> = NO_SESSION_TAG;
            const ORDINAL: U32<BE> = U32::new(2);
            const COMMAND_CODE: U16<BE> = U16::new(1);
            type TpmvResponse = FakeResponse;
        }
        impl TpmvRequestBuild for FakeRequest {
            type BuildParams = u32;
            type Err = ();

            fn init(&mut self, rest_len: u32) -> Result<(), ()> {
                self.rest_len.set(rest_len);
                Ok(())
            }

            fn expected_size(rest_len: &u32) -> Result<u32, ()> {
                Ok((size_of::<U32<BE>>()
                    + 3 * size_of::<ZeroU32>()
                    + usize::try_from(*rest_len).unwrap()) as u32)
            }
        }
        #[derive(FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
        #[repr(C)]
        struct FakeResponse;
        let mut buf = Vec::new();
        let req = TpmRequestMessage::<FakeRequest>::new_in_vec(&mut buf, 10).unwrap();
        assert_eq!(req.request.rest_len.get(), 10);
        assert_eq!(req.request.rest, [0; 10]);
        req.request.rest[0] = 10;
        assert_eq!(
            req.as_bytes(),
            [
                0x80, 1, 0, 0, 0, 38, 0, 0, 0, 2, 0, 1, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(buf.len(), 38);

        let req = TpmRequestMessage::<FakeRequest>::new_in_vec(&mut buf, 5).unwrap();
        assert_eq!(req.request.rest_len.get(), 5);
        assert_eq!(req.request.rest, [0; 5], "buf should have been zeroed");
        assert_eq!(buf.len(), 33, "buf should have been truncated");
    }

    #[test]
    fn test_request_new_in_vec_overflow() {
        #[derive(FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
        #[repr(C)]
        struct FakeRequest;
        impl TpmvRequest for FakeRequest {
            const TAG: U16<BE> = NO_SESSION_TAG;
            const ORDINAL: U32<BE> = U32::new(2);
            const COMMAND_CODE: U16<BE> = U16::new(1);
            type TpmvResponse = FakeResponse;
        }
        impl TpmvRequestBuild for FakeRequest {
            type BuildParams = ();
            type Err = ();

            fn init(&mut self, _: ()) -> Result<(), ()> {
                Ok(())
            }

            fn expected_size(_: &()) -> Result<u32, ()> {
                Ok(u32::MAX)
            }
        }
        #[derive(FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
        #[repr(C)]
        struct FakeResponse;
        let mut buf = vec![1, 2, 3];
        let res = TpmRequestMessage::<FakeRequest>::new_in_vec(&mut buf, ());
        assert!(matches!(res, Err(TpmRequestBuildError::Size)));
        assert_eq!(buf, [1, 2, 3], "expected size error should not affect buf")
    }

    #[test]
    fn test_request_new_in_vec_internal_error() {
        #[derive(Debug, FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
        #[repr(C)]
        struct FakeRequest;
        impl TpmvRequest for FakeRequest {
            const TAG: U16<BE> = NO_SESSION_TAG;
            const ORDINAL: U32<BE> = U32::new(2);
            const COMMAND_CODE: U16<BE> = U16::new(1);
            type TpmvResponse = FakeResponse;
        }
        impl TpmvRequestBuild for FakeRequest {
            type BuildParams = bool;
            type Err = &'static str;

            fn init(&mut self, fail_init: bool) -> Result<(), Self::Err> {
                if fail_init {
                    Err("init")
                } else {
                    Ok(())
                }
            }

            fn expected_size(&fail_init: &bool) -> Result<u32, Self::Err> {
                if !fail_init {
                    Err("expected_size")
                } else {
                    Ok(0)
                }
            }
        }
        #[derive(FromZeros, KnownLayout, IntoBytes, Immutable, Unaligned)]
        #[repr(C)]
        struct FakeResponse;
        let mut buf = vec![1, 2, 3];
        let res = TpmRequestMessage::<FakeRequest>::new_in_vec(&mut buf, false);
        assert!(matches!(res, Err(TpmRequestBuildError::Internal("expected_size"))));
        assert_eq!(buf, [1, 2, 3], "expected_size error should not affect buf");
        let res = TpmRequestMessage::<FakeRequest>::new_in_vec(&mut buf, true);
        assert!(matches!(res, Err(TpmRequestBuildError::Internal("init"))));
    }
}
