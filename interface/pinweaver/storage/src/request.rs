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
//! v1 storage request

use super::{LargeSecretInfo, LeafContents, LeafId, LeafSet, TreeParams};
use crate::{
    util::{serde_enums, serde_fields, serde_zerocopy, SerdeOption},
    TreeHash,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

serde_enums! {
    /// A request to the storage daemon.
    #[derive(Clone)]
    pub enum StorageRequest {
        /// Gets the status of on-disk PinWeaver data and tree info.
        GetStatus = 0,

        /// Initializes a new database for PinWeaver.
        ResetTree(ResetTreeRequest) = 1,

        /// Starts a mutating operation on the PinWeaver tree.
        ///
        /// This may commit to disk that the operation has begun.
        StartOp(StartOpRequest) = 2,

        /// Commits a mutating operation on the PinWeaver tree.
        CommitOp(CommitOpRequest) = 3,
    }

    /// Start a PinWeaver transaction.
    ///
    /// Describes a multi-step operation which may be interrupted by
    /// power loss, de-syncing disk and on-chip PinWeaver state.
    ///
    /// This responds with the necessary tree hashes to perform the
    /// operation. If necessary, this also tracks that it's begun.
    #[derive(Clone)]
    pub enum StartOpRequest {
        /// Insert a leaf into PinWeaver.
        Insert(InsertOpRequest) = 0,

        /// Authenticate a leaf.
        /// Disk state is always mutated for auth attempts.
        TryAuth(LeafId) = 1,

        /// Remove a specific leaf in PinWeaver.
        Remove(LeafId) = 2,

        /// Remove many leaves in PinWeaver.
        RemoveBulk(LeafSet) = 3,
    }

    /// Whether to allow an insert with the same leaf ID as in the
    /// [`InsertOpRequest`].
    #[derive(Clone)]
    pub enum InsertMode {
        /// Reject the insertion if a leaf with this ID exists.
        NewOnly = 0,

        /// Replace the leaf with new contents if this ID is already present.
        ReplaceExisting = 1,
    }
}

/// Clear any existing PinWeaver state and reinitialize.
///
/// An empty PinWeaver Merkle tree has tree hashes derivable
/// from these parameters and no on-chip secrets.
///
/// The response root hash should equal the value returned by the GSC.
#[derive(Clone, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ResetTreeRequest {
    /// The parameters for the newly constructed tree.
    pub tree_params: TreeParams,
}

/// Request to insert a leaf into PinWeaver.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug)]
pub struct InsertOpRequest {
    /// The leaf this operation targets.
    pub leaf_id: LeafId,

    /// Whether to allow an insert when a leaf with `leaf_id` exists.
    pub mode: InsertMode,

    /// The large key info associated with the new leaf.
    pub large_key_info: SerdeOption<LargeSecretInfo>,
}

/// Commit a PinWeaver transaction to disk.
///
/// The new tree hashes are also calculated by the storage daemon
/// and committed to disk.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug)]
pub struct CommitOpRequest {
    /// The original start request.
    ///
    /// Large key info is not included.
    pub start_request: StartOpRequest,

    /// The new HMAC of the leaf returned by PinWeaver.
    ///
    /// Zeroes if being removed.
    pub new_leaf_hmac: TreeHash,

    /// The new contents of the leaf returned by PinWeaver.
    ///
    /// Empty if being removed.
    pub new_leaf_contents: LeafContents,
}

serde_fields!(
    CommitOpRequest { start_request, new_leaf_hmac, new_leaf_contents },
    InsertOpRequest { leaf_id, mode, large_key_info },
);
serde_zerocopy!(ResetTreeRequest);
