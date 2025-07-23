//! PinWeaver response-only types.

use super::{
    request, Hash, LogEntry, Secret, TimeDiff, Timestamp, TreeParams, UnimportedLeafDataSizeError,
    WithUnimportedLeafData, PROTOCOL_VERSION,
};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned, LE, U16, U32};

/// A PinWeaver response, after the TPM header.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct Response<R: ?Sized> {
    /// The header for the response.
    ///
    /// This field is private because it's invalid in the general case
    /// to overwrite one whole `ResponseHeader` with another.
    header: ResponseHeader,

    /// The response-specific data.
    pub data: R,
}

/// Returned when the response failed its consistency check.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// Protocol version error.
    #[error("protocol version (got {0}, expected {PROTOCOL_VERSION})")]
    ProtocolVersion(u8),

    /// Total size of the response invalid.
    #[error("total size invalid (header says {in_header}, parsed {received}) ")]
    TotalSize {
        /// The size indicated in the header.
        in_header: u16,

        /// The size parsed and stored in the object.
        received: usize,
    },

    /// Leaf contains an invalid size header for the parsed message.
    #[error(transparent)]
    LeafDataSize(#[from] UnimportedLeafDataSizeError),

    /// PinWeaver on the GSC returned an error.
    #[error("operation failed: {0}")]
    ResultCode(#[source] ResultCode),
}

impl<R: ?Sized + ResponseData> Response<R> {
    /// Gets the header for the response.
    pub fn header(&self) -> &ResponseHeader {
        &self.header
    }

    /// Checks the validity of the response data.
    ///
    /// This checks, in this order:
    ///
    /// - The response header protocol version must match `PROTOCOL_VERSION`.
    /// - The response code must be `Success`.
    /// - The data sizes in the message must match the size of received data.
    ///
    /// Note that this does *not* check that a path hash length
    /// matches what is expected for the current tree parameters.
    pub fn check_consistency(&self, tree_params: &TreeParams) -> Result<(), Error> {
        if self.header.version != PROTOCOL_VERSION {
            return Err(Error::ProtocolVersion(self.header.version));
        }
        if !matches!(
            self.header.result_code,
            ResultCode::Success
                | ResultCode::SuccessWithIncrement
                | ResultCode::LowentAuthFailed
                | ResultCode::RateLimitReached
        ) {
            return Err(Error::ResultCode(self.header.result_code));
        }
        let header_data_size = self.header.data_size.get();
        let received_data_size = size_of_val(&self.data);
        if usize::from(header_data_size) != received_data_size {
            return Err(Error::TotalSize {
                in_header: header_data_size,
                received: received_data_size,
            });
        }
        // An empty unimported leaf is returned for ResultCode::RateLimitReached.
        if self.header.result_code != ResultCode::RateLimitReached {
            self.data.check_consistency(tree_params)?
        }
        Ok(())
    }
}

/// Trailing data specific to a particular kind of response.
pub trait ResponseData: FromZeros + KnownLayout + Immutable + IntoBytes + Unaligned {
    /// Request data associated with this response.
    type RequestData: ?Sized + request::RequestData<ResponseData = Self>;

    /// Checks the validity of the message-type-specific data.
    fn check_consistency(&self, _tree_params: &TreeParams) -> Result<(), Error> {
        Ok(())
    }
}

/// Identifies the correct corresponding request type from part of a response.
pub trait ResponsePart {
    /// Request data associated with this response. Does not correspond to `RequestPart`.
    ///
    /// Putting a `RequestData` bound here puts the type checker in a loop.
    type RequestData: ?Sized;
}

impl<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned + ResponsePart>
    ResponseData for WithUnimportedLeafData<Header>
where
    Header::RequestData: request::RequestData<ResponseData = Self>,
{
    type RequestData = Header::RequestData;

    /// Checks the validity of the message-type-specific data.
    fn check_consistency(&self, _tree_params: &TreeParams) -> Result<(), Error> {
        // Responses do not contain path hashes - `TreeParams` aren't used.
        self.unimported_leaf_data.check_consistency(None)?;
        Ok(())
    }
}

/// Header for all PinWeaver responses.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct ResponseHeader {
    /// The protocol version for the response.
    version: u8,

    /// The size of the response in bytes.
    ///
    /// Does *not* include the size of this header.
    data_size: U16<LE>,

    /// The result of the operation.
    pub result_code: ResultCode,

    /// The current root hash of the tree.
    pub root: Hash,
}

/// Intermediate type when parsing responses since the data may be empty on error.
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct UnparsedResponse(pub [u8]);

impl ResponseData for UnparsedResponse {
    type RequestData = request::UnparsedRequest;

    /// Checks the validity of the message-type-specific data.
    fn check_consistency(&self, _tree_params: &TreeParams) -> Result<(), Error> {
        Ok(())
    }
}

/// The response data from resetting a tree.
///
/// No extra data comes with the response.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct ResetTree;
impl ResponseData for ResetTree {
    type RequestData = request::ResetTree;
}

/// Insert leaf response data.
pub type InsertLeaf = WithUnimportedLeafData<InsertLeafHeader>;

/// The portion of insert leaf response data before the unimported leaf.
///
/// In other words, nothing - this just distinguishes from other responses.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct InsertLeafHeader;
impl ResponsePart for InsertLeafHeader {
    type RequestData = request::InsertLeaf;
}

/// The response data from removing a leaf.
///
/// No extra data comes with the response.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct RemoveLeaf;
impl ResponseData for RemoveLeaf {
    type RequestData = request::RemoveLeaf;
}

/// Try auth response data.
pub type TryAuth = WithUnimportedLeafData<TryAuthHeader>;

/// The portion of try auth response data before the unimported leaf.
///
/// The unimported leaf is used for the `LowentAuthfailed` and `Success` return codes.
// TODO: b/359374997 - confirm that unimported leaf data validation still works for other errors.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct TryAuthHeader {
    /// Used for the `RateLimitReached` return code only.
    pub seconds_to_wait: TimeDiff,

    /// Used for the `Success` return code only.
    pub high_entropy_secret: Secret,

    /// Used for the `Success` return code only.
    pub reset_secret: Secret,
}

impl ResponsePart for TryAuthHeader {
    type RequestData = request::TryAuth;
}

/// Get log response.
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct GetLog {
    /// The log entries.
    pub entries: [LogEntry],
}

impl ResponseData for GetLog {
    type RequestData = request::GetLog;
}

/// Log replay response data.
pub type LogReplay = WithUnimportedLeafData<LogReplayHeader>;

/// The portion of log replay response data before the unimported leaf.
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct LogReplayHeader {}

impl ResponsePart for LogReplayHeader {
    type RequestData = request::LogReplay;
}

/// Info about the PinWeaver system.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct SysInfo {
    /// The current timestamp as recognized by PinWeaver.
    pub current_timestamp: Timestamp,
}

impl ResponseData for SysInfo {
    type RequestData = request::SysInfo;
}

/// A PinWeaver result code.
// TODO: https://github.com/kupiakos/open-enum/issues/27 - use open_enum when it supports U32<LE>
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq, Unaligned)]
#[repr(transparent)]
pub struct ResultCode(pub U32<LE>);

#[allow(non_upper_case_globals)]
impl ResultCode {
    /// Success. Also see `SuccessWithIncrement`.
    pub const Success: Self = Self(U32::new(0));

    /// Unknown error.
    pub const Unknown: Self = Self(U32::new(1));

    /// Functionality unimplemented.
    pub const Unimplemented: Self = Self(U32::new(2));

    /// Version mismatch in request.
    pub const VersionMismatch: Self = Self(U32::new(0x10000));

    /// Invalid parameters for tree.
    pub const TreeInvalid: Self = Self(U32::new(0x10001));

    /// Request length is invalid.
    pub const LengthInvalid: Self = Self(U32::new(0x10002));

    /// Request type is invalid.
    pub const TypeInvalid: Self = Self(U32::new(0x10003));

    /// Tree bits per level invalid.
    ///
    /// Note: the implementation returns `TreeInvalid` instead of bits/height invalid.
    pub const BitsPerLevelInvalid: Self = Self(U32::new(0x10004));

    /// Tree height invalid.
    pub const HeightInvalid: Self = Self(U32::new(0x10005));

    /// Leaf label invalid for the tree.
    pub const LabelInvalid: Self = Self(U32::new(0x10006));

    /// Delay schedule is invalid.
    pub const DelayScheduleInvalid: Self = Self(U32::new(0x10007));

    /// Path authentication failed.
    pub const PathAuthFailed: Self = Self(U32::new(0x10008));

    /// Version mismatch in leaf.
    pub const LeafVersionMismatch: Self = Self(U32::new(0x10009));

    /// HMAC authentication failed.
    pub const HmacAuthFailed: Self = Self(U32::new(0x1000a));

    /// Low-entropy secret failed authentication.
    pub const LowentAuthFailed: Self = Self(U32::new(0x1000b));

    /// Resetting authentication failed.
    pub const ResetAuthFailed: Self = Self(U32::new(0x1000c));

    /// Failure in GSC crypto engine.
    pub const CryptoFailure: Self = Self(U32::new(0x1000d));

    /// Rate limit reached for leaf.
    pub const RateLimitReached: Self = Self(U32::new(0x1000e));

    /// Root hash not present in replay log.
    pub const RootNotFound: Self = Self(U32::new(0x1000f));

    /// Internal non-volatile empty.
    pub const NvEmpty: Self = Self(U32::new(0x10010));

    /// Length mismatch in internal non-volatile.
    pub const NvLengthMismatch: Self = Self(U32::new(0x10011));

    /// Version mismatch in internal non-volatile.
    pub const NvVersionMismatch: Self = Self(U32::new(0x10012));

    /// Auth failed due to mismatch in PCR values.
    pub const PcrNotMatch: Self = Self(U32::new(0x10013));

    /// Unknown internal failure.
    pub const InternalFailure: Self = Self(U32::new(0x10014));

    /// The leaf has expired.
    pub const Expired: Self = Self(U32::new(0x10015));

    /// The bio auth channel is invalid.
    pub const BioAuthChannelInvalid: Self = Self(U32::new(0x10016));

    /// Mismatch in public key version for bio auth.
    pub const BioAuthPublicKeyVersionMismatch: Self = Self(U32::new(0x10017));

    /// Access denied for bio auth.
    pub const BioAuthAccessDenied: Self = Self(U32::new(0x10018));

    /// Bio auth public key not established.
    pub const BioAuthPkNotEstablished: Self = Self(U32::new(0x10019));

    /// Success, but the attempt counter should be incremented.
    ///
    /// Log replay depends on the return code to decide whether the attempt
    /// counter should be increased, but try_auth on a biometrics leaf should
    /// always increase the counter. Therefore, use this special error code
    /// when logging a try_auth event like this.
    pub const SuccessWithIncrement: Self = Self(U32::new(0x1001a));

    /// Bio auth public key already established.
    pub const BioAuthPkAlreadyEstablished: Self = Self(U32::new(0x1001b));
}

impl ResultCode {
    fn description(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Unimplemented => "functionality unimplemented",
            Self::VersionMismatch => "version mismatch in request",
            Self::TreeInvalid => "invalid parameters for tree",
            Self::LengthInvalid => "request length is invalid",
            Self::TypeInvalid => "request type is invalid",
            Self::BitsPerLevelInvalid => "tree bits per level invalid",
            Self::HeightInvalid => "tree height invalid",
            Self::LabelInvalid => "leaf label invalid for the tree",
            Self::DelayScheduleInvalid => "delay schedule is invalid",
            Self::PathAuthFailed => "path authentication failed",
            Self::LeafVersionMismatch => "version mismatch in leaf",
            Self::HmacAuthFailed => "HMAC authentication failed",
            Self::LowentAuthFailed => "low-entropy secret failed authentication",
            Self::ResetAuthFailed => "resetting authentication failed",
            Self::CryptoFailure => "failure in GSC crypto engine",
            Self::RateLimitReached => "rate limit reached for leaf",
            Self::RootNotFound => "root hash not present in replay log",
            Self::NvEmpty => "internal non-volatile empty",
            Self::NvLengthMismatch => "length mismatch in internal non-volatile",
            Self::NvVersionMismatch => "version mismatch in internal non-volatile",
            Self::PcrNotMatch => "auth failed due to mismatch in PCR values",
            Self::InternalFailure => "unknown internal failure",
            Self::Expired => "the leaf has expired",
            Self::BioAuthChannelInvalid => "the bio auth channel is invalid",
            Self::BioAuthPublicKeyVersionMismatch => "mismatch in public key version for bio auth",
            Self::BioAuthAccessDenied => "access denied for bio auth",
            Self::BioAuthPkNotEstablished => "bio auth public key not established",
            Self::SuccessWithIncrement => "success, but the attempt counter should be incremented",
            Self::BioAuthPkAlreadyEstablished => "bio auth public key already established",
            _ => "unknown error",
        }
    }
}

impl std::fmt::Display for ResultCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:05x}: {}", self.0, self.description())
    }
}

impl std::error::Error for ResultCode {}

impl std::fmt::Debug for ResultCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self, f)
    }
}
