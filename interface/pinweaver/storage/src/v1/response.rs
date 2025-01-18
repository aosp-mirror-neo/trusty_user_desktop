/*
 * Copyright (c) 2024, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//! v1 storage response

use super::{LargeSecretInfo, LeafContents, LeafId, Path, TreeHash, TreeHashes, TreeParams, U32};
use crate::util::{serde_enums, serde_fields, serde_zerocopy, SerdeOption};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// The response from the storage daemon.
pub struct StorageResponse {
    /// Header info that is serialized contiguously.
    pub header: StorageResponseHeader,

    /// The operation-specific data for a storage response.
    pub op_data: StorageResponseData,
}

/// The header for [`StorageResponse`].
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C)]
pub struct StorageResponseHeader {
    /// The status of executing the request; check this first.
    pub status: ResponseStatus,

    /// The current root hash for the tree.
    pub root_hash: TreeHash,
}

/// The response when getting the status of PinWeaver.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C)]
pub struct GetStatusResponse {
    /// The parameters for the hash tree, as understood by the storage daemon.
    pub tree_params: TreeParams,
}

/// The status of a storage daemon operation.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(transparent)]
pub struct ResponseStatus(u8);

#[allow(non_upper_case_globals)]
impl ResponseStatus {
    /// Success.
    pub const Ok: Self = Self(0);

    /// An unknown internal error occurred.
    pub const ErrUnknown: Self = Self(1);
}

/// The response when initializing PinWeaver on disk.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C)]
pub struct InitializeResponse {
    /// The total number of leaves in this tree.
    pub num_hashes: U32,
}

/// The response when starting an operation in PinWeaver.
pub struct StartOpResponse {
    /// The path of the currently operating leaf.
    pub path: Path,

    /// The current tree hashes for the specified leaf.
    pub tree_hashes: TreeHashes,

    /// The response data specific to this operation.
    pub op_data: StartOpResponseData,
}

/// The response when committing an operation in PinWeaver.
pub struct CommitOpResponse {
    /// The path of the leaf that was just updated.
    pub path: Path,

    /// The response data specific to this operation.
    pub op_data: CommitOpResponseData,
}

serde_enums! {
    /// The operation-specific data for a storage response.
    pub enum StorageResponseData {
        /// The response when getting the status of PinWeaver.
        GetStatus(GetStatusResponse) = 0,

        /// The response when initializing PinWeaver.
        Initialize(InitializeResponse) = 1,

        /// The response when starting an operation in PinWeaver.
        StartOp(StartOpResponse) = 2,

        /// The response when committing an operation in PinWeaver.
        CommitOp(CommitOpResponse) = 3,
    }

    /// The suboperation-specific data for a start-operation response.
    pub enum StartOpResponseData {
        /// The response when starting insert of a new leaf.
        Insert(StartInsertResponseData) = 0,

        /// The response when starting removal of a leaf.
        Remove(StartRemoveResponseData) = 1,

        /// The response when starting to authenticate the low-entropy secret in a leaf.
        TryAuth(StartTryAuthResponseData) = 2,
    }

    /// The suboperation-specific data for a commit-operation response.
    pub enum CommitOpResponseData {
        /// This suboperation has no more specific data.
        None = 0,

        /// The response when committing that a leaf replacement has finished the insert stage.
        ///
        /// An insert that replaces a leaf takes place in multiple stages:
        ///
        /// 1. Start the insert of a new leaf.
        /// 2. Insert the leaf in the GSC.
        /// 3. Commit the insert of that leaf to disk, and transition to the removal stage.
        /// 4. Remove the replaced leaf in the GSC.
        /// 5. Commit the removal of the replaced leaf to disk.
        ///
        /// This is the response to stage 3, containing info about the leaf to delete.
        InsertReplace(RemoveHashes) = 1,

        /// Info about the next leaf to delete.
        RemoveBulk(CommitRemoveBulkResponseData) = 2,
    }

    /// Info about the next leaf to delete after committing the delete of a leaf.
    pub enum CommitRemoveBulkResponseData {
        /// Finished with bulk removal.
        Finished = 0,

        /// There are more bulk removals to perform.
        Continue(ContinueRemoveBulkResponse) = 1,
    }
}

/// The response when starting insert of a new leaf.
pub struct StartInsertResponseData {
    /// The leaf path that is being replaced and will be deleted, if any.
    pub replacing_path: SerdeOption<Path>,
}

/// The response when starting removal of a leaf.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C)]
pub struct StartRemoveResponseData {
    /// The HMAC of the leaf to remove.
    pub leaf_hmac: TreeHash,
}

/// The response when starting to authenticate the low-entropy secret in a leaf.
pub struct StartTryAuthResponseData {
    /// The size of the high-entropy secret stored by the client in bytes.
    pub secret_size: u32,

    /// The encrypted leaf contents stored on disk.
    pub leaf_contents: LeafContents,

    /// Info necessary to access a larger key than can fit in `leaf_contents`.
    /// A large key is only used when `secret_size > 32`.
    pub large_key_info: SerdeOption<LargeSecretInfo>,
}

/// Header for [`ContinueRemoveBulkResponse`].
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C)]
pub struct ContinueRemoveBulkResponseHeader {
    /// The next leaf to remove as part of this bulk removal.
    pub id: LeafId,

    /// The path of that leaf.
    pub path: Path,
}

/// Response when committing the bulk removal of one leaf,
/// and there are more leaves to remove.
pub struct ContinueRemoveBulkResponse {
    /// Header info that is serialized contiguously.
    pub header: ContinueRemoveBulkResponseHeader,

    /// Tree info about this leaf necessary to do the deletion.
    pub hashes: RemoveHashes,
}

/// Response when a leaf should be removed after a commit operation.
pub struct RemoveHashes {
    /// The HMAC for the leaf to remove removed.
    pub leaf_hmac: TreeHash,

    /// The tree hashes for the leaf to remove.
    pub tree_hashes: TreeHashes,
}

serde_fields! {
    StorageResponse { header, op_data },
    StartOpResponse { path, tree_hashes, op_data },
    CommitOpResponse { path, op_data },
    StartInsertResponseData { replacing_path },
    StartTryAuthResponseData { secret_size, leaf_contents, large_key_info },
    ContinueRemoveBulkResponse { header, hashes },
    RemoveHashes { leaf_hmac, tree_hashes },
}

serde_zerocopy!(
    StorageResponseHeader,
    GetStatusResponse,
    InitializeResponse,
    StartRemoveResponseData,
    ContinueRemoveBulkResponseHeader,
);
