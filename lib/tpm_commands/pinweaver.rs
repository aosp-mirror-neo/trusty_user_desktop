//! Contains the requests and responses used to access PinWeaver on the GSC.
//!
//! This is based on the Chromium PinWeaver [source][0], but was not mechanically derived.
//!
//! [0]: https://chromium.googlesource.com/chromiumos/platform/pinweaver/+/main/pinweaver_types.h

#![allow(dead_code)] // Many private fields exist to be serialized and deserialized from bytes.

use crate::{
    pinweaver::{request::UnimportedLeafDataBuildParams, response::ResponseData},
    TpmInterface, TpmRequestMessage, TpmResponseMessage, TpmvRequestBuild,
};
use paste::paste;
use std::fmt::Debug;
use zerocopy::{
    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, LE, U16, U32,
    U64,
};

pub mod request;
pub mod response;

/// The protocol version recognized by this implementation.
pub const PROTOCOL_VERSION: u8 = 2;

macro_rules! export_request_response {
    ($($name:ident),* $(,)?) => {
        paste! {$(
            #[doc = concat!("A full PinWeaver ", stringify!($name), " request.")]
            pub type [<$name Request>] = TpmRequestMessage<request::Request<request::$name>>;
            #[doc = concat!("A full PinWeaver ", stringify!($name), " response.")]
            pub type [<$name Response>] = TpmResponseMessage<response::Response<response::$name>>;
        )*}
    };
}
export_request_response!(ResetTree, InsertLeaf, RemoveLeaf, TryAuth, SysInfo);

/// Overflow error while performing size arithmetic or integer conversion.
///
/// Not expected in normal usage.
#[derive(Debug, thiserror::Error)]
#[error("unexpected arithmetic overflow")]
pub struct Overflow;

/// Parameters for a tree.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct TreeParams {
    /// The number of bits to distinguish each level of the tree.
    pub bits_per_level: u8,

    /// The height of the tree, measured as edge count from root to leaf.
    pub height: u8,
}

/// Requests and responses which include the contents of a leaf on disk.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct WithUnimportedLeafData<Head> {
    /// Data before the leaf data.
    pub head: Head,

    /// The leaf data persisted off-GSC.
    pub unimported_leaf_data: UnimportedLeafData,
}

impl<Head: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned + std::fmt::Debug>
    std::fmt::Debug for WithUnimportedLeafData<Head>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithUnimportedLeafData")
            .field("header", self.head())
            .field("unimported_leaf_data", &&self.unimported_leaf_data)
            .finish()
    }
}

impl<Head: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned>
    WithUnimportedLeafData<Head>
{
    /// Gets a reference to the head of this message.
    ///
    /// Taking a reference to a generic field gives an error because Rust doesn't
    /// know about `Unaligned` making `repr(packed)` alignment errors impossible.
    pub fn head(&self) -> &Head {
        Head::ref_from_prefix(self.as_bytes()).unwrap().0
    }

    /// Gets a mutable reference to the head of this message..
    pub fn head_mut(&mut self) -> &mut Head {
        Head::mut_from_prefix(self.as_mut_bytes()).unwrap().0
    }
}

/// Version of leaf data.
///
/// This is largely ignored by Android - all that matters is consistency with GSC data.
/// The below is adapted from the original doc:
///
/// `minor` comes first so this struct will be compatible with `u32`
/// comparisons for little endian to make version comparisons easier.
/// Changes to minor versions are allowed to add new fields, but not
/// remove existing fields, and they are allowed to be interpreted by
/// previous versions---any extra fields are truncated.
/// Leafs will reject future major versions assuming they are
/// incompatible, so fields in public data and ciphertext data in
/// the [`UnimportedLeafData`] may be removed for new major versions.
/// Upgrades across major versions will require explicit logic to
/// map the old struct to the new struct or vice versa.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct LeafVersion {
    /// Minor version - can interop with other versions with the same `major`.
    minor: U16<LE>,

    /// Major version - upgrading is incompatible.
    major: U16<LE>,
}

impl LeafVersion {
    /// Builds a new `LeafVersion`.
    pub fn new(minor: u16, major: u16) -> Self {
        Self { minor: minor.into(), major: major.into() }
    }

    /// Gets the minor version.
    pub fn minor(&self) -> u16 {
        self.minor.get()
    }

    /// Gets the major version.
    pub fn major(&self) -> u16 {
        self.major.get()
    }
}

/// Identifies the version and layout of a leaf.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct LeafHeader {
    /// The version of the leaf structure.
    leaf_version: LeafVersion,

    /// Length of the public data.
    pub_len: U16<LE>,

    /// Length of the ciphertext data.
    sec_len: U16<LE>,
}

impl LeafHeader {
    /// Gets the length of the public data in the `UnimportedLeafData` `data` field.
    pub fn pub_len(&self) -> u16 {
        self.pub_len.get()
    }

    /// Gets the length of the ciphertext data in the `UnimportedLeafData` `data` field.
    pub fn sec_len(&self) -> u16 {
        self.pub_len.get()
    }

    /// Gets the leaf version.
    pub fn leaf_version(&self) -> &LeafVersion {
        &self.leaf_version
    }
}

/// Returns the number of auxiliary hashes to include in requests that require them.
///
/// Depends on the tree parameters.
pub fn path_auxiliary_hash_count(bits_per_level: u8, height: u8) -> Result<usize, Overflow> {
    ((1usize.checked_shl(bits_per_level.into()).ok_or(Overflow)?) - 1)
        .checked_mul(height.into())
        .ok_or(Overflow)
}

/// Leaf data persisted off-GSC.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)] // The `packed` is required for DST IntoBytes at the moment.
pub struct UnimportedLeafData {
    header: LeafHeader,
    /// HMAC for the leaf - covers head, iv, and payload, excluding the path hashes.
    pub hmac: Hash,

    /// IV used to calculate the HMAC.
    pub iv: Iv,

    /// Blob of remaining data. Has the following layout:
    ///
    /// ```
    /// #[repr(C)]
    /// struct Tail {
    ///     pub_data: [u8; header.pub_len],
    ///     cipher_text: [u8; header.sec_len],
    ///     // For requests only (size expected external to this struct):
    ///     path_hashes: [
    ///       Hash; path_auxiliary_hash_count(bits_per_level, height) * sizeof::<Hash>()
    ///     ],
    /// }
    /// ```
    pub data: [u8],
}

// Cannot `derive(Debug)` for `repr(packed)`
impl std::fmt::Debug for UnimportedLeafData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnimportedLeafData")
            .field("head", &self.header)
            .field("hmac", &self.hmac)
            .field("iv", &self.iv)
            .field("data", &&self.data)
            .finish()
    }
}

/// Error in the consistency of sizes in an [`UnimportedLeafData`].
#[derive(Clone, Debug, thiserror::Error)]
pub enum UnimportedLeafDataSizeError {
    /// Bad leaf data size.
    #[error("leaf data size invalid - got {pub_len} + {sec_len}, expected {total_received}")]
    LeafDataSizes {
        /// The length of public data reported in the invalid header.
        pub_len: u16,

        /// The length of ciphertext data reported in the invalid header.
        sec_len: u16,

        /// The total length of dynamic data in the invalid [`UnimportedLeafData`].
        total_received: usize,
    },

    /// Trailing path hash sizes not divisible by the hash size.
    #[error("remaining leaf data size not divisible by hash size: {size_for_hashes}")]
    HashDataSizeNotDivisible {
        /// The size in bytes remaining for hashes after subtracting public and secure lengths.
        size_for_hashes: usize,
    },

    /// Trailing data for path hashes in the `UnimportedLeafData` wasn't the right size.
    #[error(
        "unexpected hash count in leaf data: got {num_hashes_got}, expected {num_hashes_expected}"
    )]
    HashDataLen {
        /// The number of hashes present in the leaf data.
        num_hashes_got: usize,

        /// The number of expected hashes in the leaf based on the current tree parameters.
        num_hashes_expected: usize,
    },

    /// Wrong dynamic size when building an UnimportedLeafData with path hashes from one without.
    #[error("destination has wrong size")]
    WrongDataLen {
        /// The number of bytes allocated.
        data_got: usize,

        /// The number of bytes in the leaf data + path hashes.
        data_expected: usize,
    },

    /// Invalid tree parameters.
    #[error("tried to check consistency with invalid tree params {0:?}")]
    InvalidTreeParams(TreeParams),
}

impl UnimportedLeafData {
    /// Gets the unimported leaf header.
    pub fn header(&self) -> &LeafHeader {
        &self.header
    }

    /// Gets the path hashes to fill in for a request.
    ///
    /// Returns `None` if the header does not have valid sizes.
    /// Note that this will be `Some([])` for a self-consistent response message.
    ///
    /// If `check_consistency` returned `Ok` with `Some(TreeParams)`, then the length of the
    /// returned slice will be the number of sibling hashes needed for a path in that tree.
    pub fn path_hashes_mut(&mut self) -> Option<&mut [Hash]> {
        let hashes_offset = usize::from(self.header.pub_len()) + usize::from(self.header.sec_len());
        self.data
            .get_mut(hashes_offset..)
            .and_then(|hashes_bytes| <[Hash]>::mut_from_bytes(hashes_bytes).ok())
    }

    /// Copy the provided UnimportedLeafData without path hashes and path hashes into self.
    pub fn build_from(
        &mut self,
        other: &UnimportedLeafData,
        path_hashes: &[u8],
    ) -> Result<(), UnimportedLeafDataSizeError> {
        let data_got = other.data.len() + path_hashes.len();
        if self.data.len() != data_got {
            return Err(UnimportedLeafDataSizeError::WrongDataLen {
                data_got,
                data_expected: self.data.len(),
            });
        }
        self.header = other.header;
        self.hmac = other.hmac;
        self.iv = other.iv;
        self.data[0..other.data.len()].copy_from_slice(&other.data);
        self.data[other.data.len()..].copy_from_slice(path_hashes);
        Ok(())
    }

    /// Checks the consistency of the unimported leaf data header against its dynamic size.
    ///
    /// `request_tree_params` should only be `Some` for request messages, which use path hashes.
    pub fn check_consistency(
        &self,
        request_tree_params: Option<&TreeParams>,
    ) -> Result<(), UnimportedLeafDataSizeError> {
        use UnimportedLeafDataSizeError::*;
        let total_received = self.data.len();
        let pub_len = self.header.pub_len.get();
        let sec_len = self.header.sec_len.get();
        let num_expected_hashes = request_tree_params
            .map(|&tree_params| {
                path_auxiliary_hash_count(tree_params.bits_per_level, tree_params.height)
                    .map_err(|Overflow| InvalidTreeParams(tree_params))
            })
            .transpose()?;

        let dyn_leaf_data_size = usize::from(pub_len) + usize::from(sec_len);
        match (total_received.checked_sub(dyn_leaf_data_size), num_expected_hashes) {
            (Some(0), None) => Ok(()),
            (Some(1..), None) | (None, _) => {
                Err(LeafDataSizes { pub_len, sec_len, total_received })
            }
            (Some(size_for_hashes), Some(_)) if size_for_hashes % size_of::<Hash>() != 0 => {
                Err(HashDataSizeNotDivisible { size_for_hashes })
            }
            (Some(size_for_hashes), Some(num_hashes_expected)) => {
                let num_hashes_got = size_for_hashes / size_of::<Hash>();
                if num_hashes_got == num_hashes_expected {
                    Ok(())
                } else {
                    Err(HashDataLen { num_hashes_got, num_hashes_expected })
                }
            }
        }
    }
}

/// Unencrypted part of the leaf data.
#[derive(Clone, Debug, IntoBytes, Immutable, KnownLayout, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct LeafPublicData {
    /// The label of the leaf.
    pub label: Label,

    /// The delay schedule for the new leaf.
    pub delay_schedule: DelaySchedule,

    /// The last access of the tree.
    pub last_access: Timestamp,

    /// The number of attempted auths against this leaf since the last successful auth.
    ///
    /// Capped at `u32::MAX`.
    pub attempt_count: U32<LE>,

    /// The PCR criteria used to validate a leaf.
    pub valid_pcr_criteria: ValidPcrCriteria,

    /// Timestamp when the leaf data expires and authentication is always rejected.
    ///
    /// All zeroes if expiration will not take place.
    pub expiration: Timestamp,

    /// The delay from creation of this leaf to when its expiration.
    ///
    /// 0 indicates no expiration will take place.
    ///
    /// Kept here to update `expiration` after resetting a leaf.
    pub expiration_delay: TimeDiff,

    /// The type of PinWeaver leaf.
    pub leaf_type: LeafType,
}

/// A single entry in a delay schedule table.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct DelayScheduleEntry {
    /// The number of attempts taken before this entry takes effect.
    pub attempt_count: U32<LE>,

    /// The time interval to wait after `attempt_count` attempts, in seconds.
    /// Use `u32::MAX` to block all subsequent attempts.
    pub time_diff: TimeDiff,
}

impl Default for DelayScheduleEntry {
    fn default() -> Self {
        DelayScheduleEntry::new_zeroed()
    }
}

/// The number of delay schedule entries allowed for a PinWeaver leaf.
pub const DELAY_SCHEDULE_ENTRIES: usize = 16;

/// The delay schedule for a PinWeaver leaf upon unsuccessful auth.
///
/// `attempt_count` and `time_diff` must not be less than previous entries.
pub type DelaySchedule = [DelayScheduleEntry; DELAY_SCHEDULE_ENTRIES];

/// A label in the tree. Synonymous with "path" - used interchangeably.
pub type Label = U64<LE>;

/// Contents of a PinWeaver secret.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(transparent)]
pub struct Secret(pub [u8; 32]);

/// A hash in the PinWeaver tree. Unrelated to the size of `Secret`s.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(transparent)]
pub struct Hash(pub [u8; 32]);

/// The block size of encryption used for wrapped leaf data.
const WRAP_BLOCK_SIZE: usize = 16;

/// An IV for a PinWeaver leaf's HMAC calculation.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(transparent)]
pub struct Iv(pub [u8; WRAP_BLOCK_SIZE]);

/// Time difference in seconds.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(transparent)]
pub struct TimeDiff(U32<LE>);

impl TimeDiff {
    /// Used to block all subsequent attempts in a [`DelayScheduleEntry`].
    pub const BLOCK_ATTEMPTS: Self = Self::from_secs(u32::MAX);

    /// Converts from seconds.
    pub const fn from_secs(secs: u32) -> Self {
        Self(U32::new(secs))
    }

    /// Converts to seconds.
    pub const fn to_secs(self) -> u32 {
        self.0.get()
    }
}

impl From<TimeDiff> for std::time::Duration {
    fn from(value: TimeDiff) -> Self {
        std::time::Duration::from_secs(value.to_secs().into())
    }
}

/// The maximum number of criteria for valid PCR values.
pub const MAX_PCR_CRITERIA_COUNT: usize = 2;

/// The set of PCR criteria used to validate a leaf.
pub type ValidPcrCriteria = [ValidPcrValue; MAX_PCR_CRITERIA_COUNT];

/// The type of PinWeaver leaf. As of writing, only `Normal` is supported by this version.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct LeafType(pub u8);

impl LeafType {
    /// A normal leaf.
    pub const NORMAL: Self = LeafType(0);

    /// A biometrics leaf.
    pub const BIOMETRICS: Self = LeafType(1);
}

impl Default for LeafType {
    fn default() -> Self {
        LeafType::NORMAL
    }
}

/// A field used by leaves of type LeafType::BIOMETRIC.
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct AuthChannel(pub u8);

/// Represents a set of PCR values hashed into a single digest.
///
/// This is a criterion that can be added to a leaf. A leaf is only valid if at least one
/// of the `ValidPcrValue` criteria it contains is satisfied.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct ValidPcrValue {
    /// The set of PCR indexes that have to pass the validation.
    pub bitmask: [u8; 2],

    /// The hash digest of the PCR values contained in the bitmask.
    pub digest: Hash,
}

impl Default for ValidPcrValue {
    fn default() -> Self {
        // No criteria needs to be satisfied.
        ValidPcrValue::new_zeroed()
    }
}

/// Represents a notion of time for PinWeaver.
///
/// Note that this is not wall clock time.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct Timestamp {
    /// Number of boots.
    ///
    /// Used to track if the GSC has rebooted since `timer_value` was recorded.
    pub boot_count: U32<LE>,

    /// Seconds since boot.
    pub timer_value: U64<LE>,
}

/// The Operation type of a log entry.
#[derive(Clone, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct LogOperation(pub u8);

impl LogOperation {
    const INVALID: LogOperation = LogOperation(0u8);
    const RESET_TREE: LogOperation = LogOperation(1u8);
    const INSERT_LEAF: LogOperation = LogOperation(2u8);
    const REMOVE_LEAF: LogOperation = LogOperation(3u8);
    const TRY_AUTH_00: LogOperation = LogOperation(4u8);
    const TRY_AUTH_02: LogOperation = LogOperation(5u8);
}

impl Debug for LogOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &LogOperation::INVALID => write!(f, "INVALID"),
            &LogOperation::RESET_TREE => write!(f, "RESET_TREE"),
            &LogOperation::INSERT_LEAF => write!(f, "INSERT_LEAF"),
            &LogOperation::TRY_AUTH_00 => write!(f, "TRY_AUTH_00"),
            &LogOperation::TRY_AUTH_02 => write!(f, "TRY_AUTH_02"),
            other => write!(f, "LogOperation({:02x})", other.0),
        }
    }
}

/// An entry in the operation log kept by the GSC.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct LogEntry {
    /// The root hash after this operation.
    pub root: Hash,
    /// The path operated on.
    pub label: Label,
    /// The type of the operation.
    pub operation: LogOperation,
    /// The operation data.
    data: Hash,
}

/// Handler for the different variants of LogEntry.
pub enum LogEntryData<'a> {
    /// A placeholder to indicate self.data isn't used when the operation is ResetTree.
    ResetTree,
    /// The value of self.data when operation is InsertLeaf.
    InsertLeaf(&'a Hash),
    /// A placeholder to indicate self.data isn't used when the operation is RemoveLeaf.
    RemoveLeaf,
    /// The value of self.data when operation is TryAuth in protocol version 00 and 01.
    TryAuth00(&'a LogEntryTryAuthData00),
    /// The value of self.data when operation is TryAuth in protocol version 02.
    TryAuth02(&'a LogEntryTryAuthData02),
    /// A placeholder for operations that aren't expected to be in the log.
    UnrecognizedOperation,
}

impl LogEntry {
    /// Interpret the data field based on the operation.
    pub fn data(&self) -> LogEntryData<'_> {
        match self.operation {
            LogOperation::INSERT_LEAF => LogEntryData::InsertLeaf(&self.data),
            LogOperation::REMOVE_LEAF => LogEntryData::RemoveLeaf,
            LogOperation::TRY_AUTH_00 => {
                LogEntryData::TryAuth00(FromBytes::ref_from_prefix(&self.data.0).unwrap().0)
            }
            LogOperation::TRY_AUTH_02 => {
                LogEntryData::TryAuth02(FromBytes::ref_from_prefix(&self.data.0).unwrap().0)
            }
            _ => LogEntryData::UnrecognizedOperation,
        }
    }
}

/// Data stored in LogEntry::leaf_hmac when LogEntry::operation is TryAuth.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct LogEntryTryAuthData00 {
    /// The time of last access.
    pub last_access_time: Timestamp,
    /// The result code of the operation.
    pub return_code: response::ResultCode,
}

/// Data stored in LogEntry::leaf_hmac when LogEntry::operation is TryAuth.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct LogEntryTryAuthData02 {
    /// The time of last access.
    pub last_access_time: Timestamp,
    /// The result code of the operation.
    pub return_code: response::ResultCode,
    /// The expiration time of the leaf.
    pub expiration_time: Timestamp,
}

/// Wrapper around errors when using Pinweaver on the GSC.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error that comes from the underlying transport scheme like TIPC.
    #[error("transport error: {0:?}")]
    Transport(Box<dyn Debug + 'static>),
    /// The deserialization of a response failed.
    #[error("failed to deserialize")]
    Deserialize,
    /// Some of the math operations overflowed with the given parameters.
    #[error("overflow while constructiong request")]
    RequestOverflow,
    /// The response isn't consistent.
    #[error("response consistency check failed: {0:?}")]
    Response(#[from] response::Error),
}

type PinWeaverResult<T> = Result<T, Error>;

/// Abstract the TPM/GSC Pinweaver interface.
pub trait Pinweaver {
    /// An abstraction of the Error type returned by Pinweaver RPCs.
    type TransportError: Debug;

    /// Insert a leaf into the merkle tree.
    fn insert_leaf<'a>(
        &self,
        tree_params: TreeParams,
        header: request::InsertLeafHeader,
        path_hashes: &[Hash],
        resp_buffer: &'a mut Vec<u8>,
    ) -> PinWeaverResult<(Hash, &'a UnimportedLeafData)>;

    /// Try to authenticate a low entropy secret.
    fn try_auth<'a>(
        &self,
        tree_params: TreeParams,
        header: request::TryAuthHeader,
        leaf_data: &[u8],
        path_hashes: &[Hash],
        resp_buffer: &'a mut Vec<u8>,
    ) -> PinWeaverResult<(Hash, response::ResultCode, &'a response::TryAuth)>;

    /// Reset the low entropy authentication retries.
    fn reset_auth<'a>(
        &self,
        tree_params: TreeParams,
        header: request::ResetAuthHeader,
        leaf_data: &[u8],
        path_hashes: &[Hash],
        resp_buffer: &'a mut Vec<u8>,
    ) -> PinWeaverResult<(Hash, &'a response::ResetAuth)>;

    /// Remove a leaf from the merkle tree.
    fn remove_leaf(
        &self,
        tree_params: TreeParams,
        header: request::RemoveLeafHeader,
        path_hashes: &[Hash],
    ) -> PinWeaverResult<Hash>;

    /// Erase the existing pinweaver tree and create a new one with the specified parameters.
    fn reset_tree(&self, tree_params: TreeParams) -> PinWeaverResult<Hash>;

    /// Get the log entries which can be used for log replay.
    fn get_log<'a>(
        &self,
        local_root: Option<Hash>,
        resp_buffer: &'a mut Vec<u8>,
    ) -> PinWeaverResult<&'a [LogEntry]>;

    /// Recover unimported leaf data by replaying an operation.
    fn log_replay<'a>(
        &self,
        tree_params: TreeParams,
        header: request::LogReplayHeader,
        leaf_data: &[u8],
        path_hashes: &[Hash],
        resp_buffer: &'a mut Vec<u8>,
    ) -> PinWeaverResult<&'a UnimportedLeafData>;

    /// Get current pinweaver timestamp from GSC.
    fn sys_info(&self) -> PinWeaverResult<(Hash, Timestamp)>;
}

fn transport_error<D: Debug + 'static>(err: D) -> Error {
    Error::Transport(Box::<D>::new(err))
}

impl<I: TpmInterface> Pinweaver for I
where
    I::Error: Debug + 'static,
{
    type TransportError = I::Error;

    fn insert_leaf<'a>(
        &self,
        tree_params: TreeParams,
        header: request::InsertLeafHeader,
        path_hashes: &[Hash],
        resp_buffer: &'a mut Vec<u8>,
    ) -> PinWeaverResult<(Hash, &'a UnimportedLeafData)> {
        let mut req_buffer = Vec::<u8>::new();
        let req = TpmRequestMessage::<request::Request<request::InsertLeaf>>::new_in_vec(
            &mut req_buffer,
            tree_params,
        )
        .map_err(|_| Error::RequestOverflow)?;

        let data = &mut req.request.data;
        *data.header_mut() = header;
        if data.path_hashes.len() != path_hashes.len() {
            return Err(Error::RequestOverflow);
        }
        data.path_hashes.copy_from_slice(path_hashes);

        let resp: &mut response::Response<response::UnparsedResponse> =
            self.transmit_into(req, resp_buffer).map_err(transport_error)?;
        resp.check_consistency(&tree_params)?;
        let header = resp.header();
        let data =
            UnimportedLeafData::ref_from_bytes(&resp.data.0).map_err(|_| Error::Deserialize)?;
        data.check_consistency(None).map_err(|_| Error::Deserialize)?;
        Ok((header.root, data))
    }

    fn try_auth<'a>(
        &self,
        tree_params: TreeParams,
        header: request::TryAuthHeader,
        leaf_data: &[u8],
        path_hashes: &[Hash],
        resp_buffer: &'a mut Vec<u8>,
    ) -> PinWeaverResult<(Hash, response::ResultCode, &'a response::TryAuth)> {
        let leaf_data =
            UnimportedLeafData::ref_from_bytes(leaf_data).map_err(|_| Error::Deserialize)?;

        let mut req_buffer = Vec::<u8>::new();
        let req = TpmRequestMessage::<request::Request<request::TryAuth>>::new_in_vec(
            &mut req_buffer,
            UnimportedLeafDataBuildParams::new(leaf_data.header(), tree_params),
        )
        .map_err(|_| Error::RequestOverflow)?;

        let data = &mut req.request.data;
        *data.head_mut() = header;
        data.unimported_leaf_data
            .build_from(leaf_data, path_hashes.as_bytes())
            .map_err(|_| Error::RequestOverflow)?;

        let resp: &mut response::Response<response::UnparsedResponse> =
            self.transmit_into(req, resp_buffer).map_err(transport_error)?;
        resp.check_consistency(&tree_params)?;
        let root: Hash = resp.header().root;
        let code = resp.header().result_code;
        let try_auth =
            response::TryAuth::ref_from_bytes(&resp.data.0).map_err(|_| Error::Deserialize)?;
        // An empty unimported leaf is returned for ResultCode::RateLimitReached.
        if code != response::ResultCode::RateLimitReached {
            try_auth.check_consistency(&tree_params)?;
        }
        Ok((root, code, try_auth))
    }

    fn reset_auth<'a>(
        &self,
        tree_params: TreeParams,
        header: request::ResetAuthHeader,
        leaf_data: &[u8],
        path_hashes: &[Hash],
        resp_buffer: &'a mut Vec<u8>,
    ) -> PinWeaverResult<(Hash, &'a response::ResetAuth)> {
        let leaf_data =
            UnimportedLeafData::ref_from_bytes(leaf_data).map_err(|_| Error::Deserialize)?;

        let mut req_buffer = Vec::<u8>::new();
        let req = TpmRequestMessage::<request::Request<request::ResetAuth>>::new_in_vec(
            &mut req_buffer,
            UnimportedLeafDataBuildParams::new(leaf_data.header(), tree_params),
        )
        .map_err(|_| Error::RequestOverflow)?;

        let data = &mut req.request.data;
        *data.head_mut() = header;
        data.unimported_leaf_data
            .build_from(leaf_data, path_hashes.as_bytes())
            .map_err(|_| Error::RequestOverflow)?;

        let resp: &mut response::Response<response::UnparsedResponse> =
            self.transmit_into(req, resp_buffer).map_err(transport_error)?;
        resp.check_consistency(&tree_params)?;
        let root: Hash = resp.header().root;
        let reset_auth =
            response::ResetAuth::ref_from_bytes(&resp.data.0).map_err(|_| Error::Deserialize)?;
        reset_auth.check_consistency(&tree_params)?;
        Ok((root, reset_auth))
    }

    fn remove_leaf(
        &self,
        tree_params: TreeParams,
        header: request::RemoveLeafHeader,
        path_hashes: &[Hash],
    ) -> PinWeaverResult<Hash> {
        let mut req_buffer = Vec::<u8>::new();
        let req = TpmRequestMessage::<request::Request<request::RemoveLeaf>>::new_in_vec(
            &mut req_buffer,
            tree_params,
        )
        .map_err(|_| Error::RequestOverflow)?;

        let data = &mut req.request.data;
        *data.header_mut() = header;
        if data.path_hashes.len() != path_hashes.len() {
            return Err(Error::RequestOverflow);
        }
        data.path_hashes.copy_from_slice(path_hashes);

        let mut resp_buffer = Vec::<u8>::new();
        let resp: &mut response::Response<response::RemoveLeaf> =
            self.transmit_into(req, &mut resp_buffer).map_err(transport_error)?;
        resp.check_consistency(&tree_params)?;
        let header = resp.header();
        Ok(header.root)
    }

    fn reset_tree(&self, tree_params: TreeParams) -> PinWeaverResult<Hash> {
        let mut req = request::Request::<request::ResetTree>::new_zeroed();
        req.data = request::ResetTree { tree_params };
        req.init(()).map_err(|_| Error::RequestOverflow)?;
        let resp: response::Response<response::ResetTree> =
            self.transmit(req).map_err(transport_error)?;
        resp.check_consistency(&tree_params)?;
        let header = resp.header();
        Ok(header.root)
    }

    fn get_log<'a>(
        &self,
        local_root: Option<Hash>,
        resp_buffer: &'a mut Vec<u8>,
    ) -> PinWeaverResult<&'a [LogEntry]> {
        let mut req_buffer = Vec::<u8>::new();
        let req =
            TpmRequestMessage::<request::Request<request::GetLog>>::new_in_vec(&mut req_buffer, ())
                .map_err(|_| Error::RequestOverflow)?;
        let data = &mut req.request.data;
        data.local_root = local_root.unwrap_or(Hash::new_zeroed());
        let resp: &mut response::Response<response::GetLog> =
            self.transmit_into(req, resp_buffer).map_err(transport_error)?;
        resp.check_consistency(&TreeParams { height: 0, bits_per_level: 0 })?;
        Ok(&resp.data.entries)
    }

    fn log_replay<'a>(
        &self,
        tree_params: TreeParams,
        header: request::LogReplayHeader,
        leaf_data: &[u8],
        path_hashes: &[Hash],
        resp_buffer: &'a mut Vec<u8>,
    ) -> PinWeaverResult<&'a UnimportedLeafData> {
        let leaf_data =
            UnimportedLeafData::ref_from_bytes(leaf_data).map_err(|_| Error::Deserialize)?;

        let mut req_buffer = Vec::<u8>::new();
        let req = TpmRequestMessage::<request::Request<request::LogReplay>>::new_in_vec(
            &mut req_buffer,
            UnimportedLeafDataBuildParams::new(leaf_data.header(), tree_params),
        )
        .map_err(|_| Error::RequestOverflow)?;

        let data = &mut req.request.data;
        *data.head_mut() = header;
        data.unimported_leaf_data
            .build_from(leaf_data, path_hashes.as_bytes())
            .map_err(|_| Error::RequestOverflow)?;

        let resp: &mut response::Response<response::UnparsedResponse> =
            self.transmit_into(req, resp_buffer).map_err(transport_error)?;
        resp.check_consistency(&tree_params)?;
        let log_replay =
            response::LogReplay::ref_from_bytes(&resp.data.0).map_err(|_| Error::Deserialize)?;
        log_replay.check_consistency(&tree_params)?;
        Ok(&log_replay.unimported_leaf_data)
    }

    fn sys_info(&self) -> PinWeaverResult<(Hash, Timestamp)> {
        let mut req = request::Request::<request::SysInfo>::new_zeroed();
        req.init(()).map_err(|_| Error::RequestOverflow)?;
        let resp: response::Response<response::SysInfo> =
            self.transmit(req).map_err(transport_error)?;
        resp.check_consistency(&TreeParams { height: 0, bits_per_level: 0 })?;
        Ok((resp.header().root, resp.data.current_timestamp))
    }
}
