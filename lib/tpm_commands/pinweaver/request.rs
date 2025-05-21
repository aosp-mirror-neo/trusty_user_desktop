//! PinWeaver request-only types.

use super::{
    path_auxiliary_hash_count, response, DelaySchedule, Hash, Iv, Label, LeafHeader, LeafVersion,
    Overflow, Secret, TreeParams, ValidPcrCriteria, WithUnimportedLeafData, PROTOCOL_VERSION,
};
use crate::{TpmvRequest, TpmvRequestBuild, NO_SESSION_TAG, VENDOR_COMMAND_ORDINAL};
use zerocopy::{
    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned, BE, LE, U16, U32,
};

/// A PinWeaver request, after the TPM header.
#[derive(FromZeros, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct Request<R: ?Sized> {
    // Private since there is no need to access these fields after `init`.
    header: RequestHeader,

    /// The data specific to the request type.
    pub data: R,
}

/// Trailing data specific to a particular kind of request.
pub trait RequestData: FromZeros + KnownLayout + Immutable + IntoBytes + Unaligned {
    /// Parameters to build an instance of this request.
    type BuildParams;

    /// The response data associated with this request.
    ///
    /// The response doesn't indicate the message type.
    /// The full response is a `pinweaver::response::Response<Self::ResponseData>`.
    type ResponseData: ?Sized + response::ResponseData<RequestData = Self>;

    /// The type of message that should always be filled in this request.
    const MESSAGE_TYPE: MessageType;

    /// Initialize a zeroed `self` to an internally consistent state.
    fn init(&mut self, _params: Self::BuildParams) -> Result<(), Overflow> {
        Ok(())
    }

    /// The expected size of this part of the request.
    fn expected_size(params: &Self::BuildParams) -> Result<u32, Overflow>;
}

impl<R: ?Sized + RequestData> TpmvRequest for Request<R> {
    const TAG: U16<BE> = NO_SESSION_TAG;
    const COMMAND_CODE: U16<BE> = U16::new(0x0025);
    const ORDINAL: U32<BE> = VENDOR_COMMAND_ORDINAL;
    type TpmvResponse = response::Response<R::ResponseData>;
}

impl<R: ?Sized + RequestData> TpmvRequestBuild for Request<R> {
    type BuildParams = R::BuildParams;
    type Err = Overflow;

    fn init(&mut self, params: Self::BuildParams) -> Result<(), Overflow> {
        self.header = RequestHeader {
            data_size: size_of_val(&self.data).try_into().map_err(|_| Overflow)?,
            version: PROTOCOL_VERSION,
            message_type: R::MESSAGE_TYPE,
        };
        self.data.init(params)?;
        Ok(())
    }

    fn expected_size(params: &Self::BuildParams) -> Result<u32, Overflow> {
        (u32::try_from(size_of::<RequestHeader>()).unwrap())
            .checked_add(R::expected_size(params)?)
            .ok_or(Overflow)
    }
}

/// Requests that end in a set of hashes along the path for a leaf.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)] // The `packed` is required for DST IntoBytes at the moment.
pub struct WithPathHashes<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned> {
    header: Header,

    /// Sibling hashes along the path, left-to-right, bottom-to-top.
    pub path_hashes: [Hash],
}

impl<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned> WithPathHashes<Header> {
    /// Gets a reference to the header.
    ///
    /// Taking a reference to a generic field gives an error because Rust doesn't
    /// know about `Unaligned` making `repr(packed)` alignment errors impossible.
    pub fn header(&self) -> &Header {
        Header::ref_from_prefix(self.as_bytes()).unwrap().0
    }

    /// Gets a mutable reference to the header.
    pub fn header_mut(&mut self) -> &mut Header {
        Header::mut_from_prefix(self.as_mut_bytes()).unwrap().0
    }
}

// Debug can't be derived with `repr(packed)`, which is needed for the current version of zerocopy.
impl<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned + std::fmt::Debug>
    std::fmt::Debug for WithPathHashes<Header>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithPathHashes")
            .field("header", self.header())
            .field("path_hashes", &&self.path_hashes)
            .finish()
    }
}

/// Identifies the correct message type and response type from part of a request.
pub trait RequestPart {
    /// The type of message that should always be filled in this request.
    const MESSAGE_TYPE: MessageType;

    /// Response data associated with this request. Does not correspond to `ResponsePart`.
    ///
    /// Putting a `ResponseData` bound here puts the type checker in a loop.
    type ResponseData: ?Sized;
}

impl<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned + RequestPart> RequestData
    for WithPathHashes<Header>
where
    Header::ResponseData: response::ResponseData<RequestData = Self>,
{
    type BuildParams = TreeParams;
    type ResponseData = Header::ResponseData;
    const MESSAGE_TYPE: MessageType = Header::MESSAGE_TYPE;

    fn init(&mut self, _: TreeParams) -> Result<(), Overflow> {
        // No header requires init.
        Ok(())
    }

    fn expected_size(params: &TreeParams) -> Result<u32, Overflow> {
        let tail_size = path_auxiliary_hash_count(params.bits_per_level, params.height)?
            .checked_mul(size_of::<Hash>())
            .ok_or(Overflow)?;
        size_of::<Header>().checked_add(tail_size).ok_or(Overflow)?.try_into().map_err(|_| Overflow)
    }
}

/// Parameters to build a new `UnimportedLeafData`.
pub struct UnimportedLeafDataBuildParams {
    /// The version of the leaf contents.
    ///
    /// Used by the GSC to process the message.
    pub leaf_version: LeafVersion,

    /// Length of the public data.
    pub pub_len: u16,

    /// Length of the ciphertext data.
    pub sec_len: u16,

    /// Parameters for the tree.
    ///
    /// Only used in requests.
    pub tree_params: TreeParams,
}

impl<Header: FromBytes + KnownLayout + Immutable + IntoBytes + Unaligned + RequestPart> RequestData
    for WithUnimportedLeafData<Header>
where
    Header::ResponseData: response::ResponseData<RequestData = Self>,
{
    type BuildParams = UnimportedLeafDataBuildParams;
    type ResponseData = Header::ResponseData;
    const MESSAGE_TYPE: MessageType = Header::MESSAGE_TYPE;

    fn expected_size(params: &UnimportedLeafDataBuildParams) -> Result<u32, Overflow> {
        let TreeParams { bits_per_level, height } = params.tree_params;
        let path_hashes = path_auxiliary_hash_count(bits_per_level, height)?;
        let static_len = const {
            size_of::<Header>() + size_of::<LeafHeader>() + size_of::<Hash>() + size_of::<Iv>()
        };
        let pub_sec_len = usize::from(params.pub_len) + usize::from(params.sec_len);
        let path_hashes_size = path_hashes.checked_mul(size_of::<Hash>()).ok_or(Overflow)?;
        let dyn_len = pub_sec_len.checked_add(path_hashes_size).ok_or(Overflow)?;
        let total_len = static_len.checked_add(dyn_len).ok_or(Overflow)?;
        total_len.try_into().map_err(|_| Overflow)
    }

    fn init(&mut self, params: UnimportedLeafDataBuildParams) -> Result<(), Overflow> {
        self.unimported_leaf_data.header = LeafHeader {
            leaf_version: params.leaf_version,
            pub_len: params.pub_len.into(),
            sec_len: params.sec_len.into(),
        };
        Ok(())
    }
}

/// Header for all PinWeaver requests.
#[derive(Clone, Copy, Debug, FromZeros, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct RequestHeader {
    /// The protocol version for the request.
    version: u8,

    /// The type of contained message.
    message_type: MessageType,

    /// The size of the request in bytes.
    ///
    /// Does *not* include the size of this header.
    data_size: U16<LE>,
}

/// The type of PinWeaver request - identifies what the rest of the message should contain.
#[repr(u8)]
#[derive(Clone, Copy, Debug, FromZeros, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub enum MessageType {
    /// Invalid message type
    Invalid = 0,

    /// Reset a PinWeaver tree
    ResetTree = 1,

    /// Insert a leaf into the tree.
    InsertLeaf = 2,

    /// Remove a leaf from the tree.
    RemoveLeaf = 3,

    /// Try to authenticate a leaf against the tree.
    TryAuth = 4,

    /// Reset the authentication attempts for a leaf.
    ResetAuth = 5,

    /// Gets the replay log for data loss.
    GetLog = 6,

    /// Replays a specific operation based on the log to recover the tree.
    LogReplay = 7,

    /// Get info about the system.
    SysInfo = 8,

    // The following are vendor-specific commands for biometrics features.
    /// Generate bioauthentication private key.
    GenerateBaPk = 9,

    /// Start biometric authentication.
    StartBioAuth = 10,

    /// Block future `GenerateBaPk` requests until next reset.
    BlockGenerateBaPk = 11,
}

/// Requests that the tree be reset.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct ResetTree {
    tree_params: TreeParams,
}

impl RequestData for ResetTree {
    type BuildParams = ();
    type ResponseData = response::ResetTree;
    const MESSAGE_TYPE: MessageType = MessageType::ResetTree;

    fn expected_size(_: &()) -> Result<u32, Overflow> {
        Ok(size_of::<Self>().try_into().unwrap())
    }
}

/// Requests a new leaf be inserted into the tree.
pub type InsertLeaf = WithPathHashes<InsertLeafHeader>;

/// Header for insert leaf request data.
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct InsertLeafHeader {
    /// The label of the leaf to insert.
    pub label: Label,

    /// The delay schedule for the new leaf.
    pub delay_schedule: DelaySchedule,

    /// The low entropy secret protecting the new leaf.
    pub low_entropy_secret: Secret,

    /// The high entropy secret stored in the new leaf.
    pub high_entropy_secret: Secret,

    /// The secret that can reset authentication for a leaf.
    pub reset_secret: Secret,

    /// The Platform Configuration Register criteria used to validate a leaf.
    pub valid_pcr_criteria: ValidPcrCriteria,
}

impl RequestPart for InsertLeafHeader {
    const MESSAGE_TYPE: MessageType = MessageType::InsertLeaf;
    type ResponseData = response::InsertLeaf;
}

/// Remove leaf request data.
pub type RemoveLeaf = WithPathHashes<RemoveLeafHeader>;

/// Header for remove leaf request data.
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct RemoveLeafHeader {
    /// The label/path of the target leaf to remove.
    pub leaf_location: Label,

    /// The HMAC of the target leaf.
    pub leaf_hmac: Hash,
}

impl RequestPart for RemoveLeafHeader {
    const MESSAGE_TYPE: MessageType = MessageType::RemoveLeaf;
    type ResponseData = response::RemoveLeaf;
}

/// Try auth request data.
pub type TryAuth = WithUnimportedLeafData<TryAuthHeader>;

/// Header for try auth request data.
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct TryAuthHeader {
    /// The low entropy secret for PinWeaver to check against the encrypted leaf contents.
    pub low_entropy_secret: Secret,
}

impl RequestPart for TryAuthHeader {
    const MESSAGE_TYPE: MessageType = MessageType::TryAuth;
    type ResponseData = response::TryAuth;
}

/// Request system info from PinWeaver.
///
/// This type selects the correct message.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct SysInfo;

impl RequestData for SysInfo {
    type BuildParams = ();
    type ResponseData = response::SysInfo;

    const MESSAGE_TYPE: MessageType = MessageType::SysInfo;

    fn expected_size(_: &()) -> Result<u32, Overflow> {
        Ok(size_of::<Self>().try_into().unwrap())
    }
}
