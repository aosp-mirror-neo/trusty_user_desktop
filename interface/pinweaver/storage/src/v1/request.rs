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

use super::{LeafContents, LeafId, TreeParams};
use crate::util::{serde_enums, serde_fields, serde_zerocopy};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

serde_enums! {
    /// A request to the storage daemon.
    pub enum StorageRequest {
        /// Gets the status of on-disk PinWeaver data and tree info.
        GetStatus = 0,

        /// Initializes a new database for PinWeaver.
        Initialize(InitializeRequest) = 1,

        /// Starts a mutating operation on the PinWeaver tree.
        ///
        /// This may commit to disk that the operation has begun.
        StartOp(StartOpRequest) = 2,

        /// Commits a mutating operation on the PinWeaver tree.
        CommitOp(CommitOpRequest) = 3,
    }
}

/// Clear any existing PinWeaver state and reinitialize.
///
/// An empty PinWeaver Merkle tree has tree hashes derivable
/// from these parameters and no on-chip secrets.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C)]
pub struct InitializeRequest {
    tree_params: TreeParams,
}

/// The kind of operation that PinWeaver is performing and needs disk info for.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes, PartialEq, Eq)]
#[repr(transparent)]
pub struct OperationKind(u8);

#[allow(non_upper_case_globals)]
impl OperationKind {
    /// Inserting a new leaf. Reject existing leaves with the same ID.
    pub const InsertNew: Self = Self(0);

    /// Inserting a new leaf. Replace a leaf with the same ID.
    pub const Insert: Self = Self(1);

    /// Trying to authenticate a low-entropy secret with a leaf.
    pub const TryAuth: Self = Self(2);

    /// Removing a specific leaf.
    pub const Remove: Self = Self(3);

    /// Removing a set of leaves.
    pub const RemoveBulk: Self = Self(4);
}

/// Start a PinWeaver transaction.
///
/// This returns the necessary tree hashes to perform the operation.
/// If necessary, this also tracks that the operation has begun.
#[derive(FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C)]
pub struct StartOpRequest {
    /// The leaf this operation targets.
    pub leaf_id: LeafId,

    /// The kind of operation being performed on this leaf.
    pub op_kind: OperationKind,
}

/// Commit a PinWeaver transaction to disk.
///
/// The new tree hashes are also calculated by the storage daemon
/// and committed to disk.
pub struct CommitOpRequest {
    /// The original start request.
    pub request: StartOpRequest,

    /// The new contents of the leaf returned by PinWeaver.
    ///
    /// Empty if being removed.
    pub new_leaf_contents: LeafContents,
}

serde_fields!(CommitOpRequest { request, new_leaf_contents });
serde_zerocopy!(InitializeRequest, StartOpRequest);
