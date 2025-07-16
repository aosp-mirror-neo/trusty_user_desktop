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

//! Defines types used to communicate between the PinWeaver storage daemon and Trusty app.
//!
//! This protocol is not version-controlled: it must change in lockstep with `libpinweaver_storage`.

use crate::util::{serde_fields, serde_zerocopy, SerdeVec};
use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub mod request;
pub mod response;
pub mod util;

/// The port on the PinWeaver Trusty app that the storage daemon connects to.
pub const PORT: &str = "com.android.desktop.security.PinWeaverStorage.V1";

// These are also the parameters used currently on ChromeOS devices.

/// The default height for the hash tree.
pub const MAX_TREE_HEIGHT: u8 = 7;

/// The default number of bits used to index into the tree per level of the tree.
pub const MAX_TREE_BITS_PER_LEVEL: u8 = 2;

/// The number of auxiliary hashes that need to be updated per-request.
pub const MAX_AUX_HASHES: u32 =
    ((1 << MAX_TREE_BITS_PER_LEVEL as u32) - 1) * MAX_TREE_HEIGHT as u32;

/// Kept in sync with the size of [`wrapped_leaf_data_t`]
///
/// [`wrapped_leaf_data_t`]: https://chromium.googlesource.com/chromiumos/platform/pinweaver/+/refs/heads/main/pinweaver.h#88
pub const LEAF_SIZE: u32 = 389;

/// The maximum supported high-entropy key size provided by the client.
///
/// Increasing this much further will require protocol restructuring
/// as it can't be sent in a single datagram over vsock.
pub const MAX_LARGE_SECRET_SIZE: u32 = 1024;

/// Replacement operators need a temporary leaf_id since it is a unique field.
pub const RESERVED_LEAF_ID: LeafId =
    LeafId { leaf_set: LeafSet(U32::new(u32::MAX)), inner_id: U32::new(u32::MAX) };

/// The interface to communicate with the storage daemon.
pub trait StorageInterface {
    /// The error while executing a storage request.
    type Error: Debug;

    /// Execute a storage request.
    fn request(&self, request: &StorageRequest) -> Result<StorageResponse, Self::Error>;
}

pub use request::StorageRequest;
pub use response::StorageResponse;

/// Unaligned little-endian `u32` - used for [`IntoBytes`] structs to prevent padding.
#[derive(
    Clone,
    Copy,
    Debug,
    FromBytes,
    KnownLayout,
    Immutable,
    IntoBytes,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[repr(transparent)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(from = "u32", into = "u32")
)]
pub struct U32(zerocopy::byteorder::U32<zerocopy::byteorder::LE>);
impl U32 {
    /// Constructs an unaligned `u32`.
    pub const fn new(val: u32) -> Self {
        Self(zerocopy::byteorder::U32::new(val))
    }

    /// Gets the underlying `u32` value.
    pub fn get(&self) -> u32 {
        self.0.get()
    }
}

impl Deref for U32 {
    type Target = zerocopy::byteorder::U32<zerocopy::byteorder::LE>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for U32 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::Display for U32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <u32 as std::fmt::Display>::fmt(&self.get(), f)
    }
}

impl From<U32> for u32 {
    fn from(val: U32) -> Self {
        val.get()
    }
}

impl From<u32> for U32 {
    fn from(val: u32) -> Self {
        Self::new(val)
    }
}

/// A leaf identifier, distinct from a [`Path`] and specific to the Android PinWeaver API.
///
/// Both the leaf set and inner ID are client-chosen.
///
/// This has a 1:1 mapping with some [`Path`] on this device,
/// except when a leaf with some ID is currently being replaced.
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct LeafId {
    /// The group this leaf ID belongs to.
    pub leaf_set: LeafSet,

    /// The semantic meaning of the `inner_id` is specific to the `leaf_set`.
    pub inner_id: U32,
}

/// The group this leaf ID belongs to.
///
/// See `LeafSet.aidl`.
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize), serde(transparent))]
pub struct LeafSet(pub U32);

/// A PinWeaver leaf path, indicating where in the hash tree a leaf is located.
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize), serde(transparent))]
pub struct Path(pub [u8; 8]);

/// The encrypted contents of a PinWeaver leaf on-disk.
pub type LeafContents = SerdeVec<u8, LEAF_SIZE>;

/// Parameters for a PinWeaver hash tree.
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TreeParams {
    /// The height of the new tree.
    pub height: u8,

    /// The number of bits in the path used per tree level.
    /// This is log2(fan-out factor).
    pub bits_per_level: u8,
}

#[derive(Clone, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize), serde(transparent))]
/// A SHA-256 digest.
pub struct TreeHash(#[cfg_attr(feature = "serde", serde(with = "util::hex_serde"))] pub [u8; 32]);

/// Tree hash for empty leaves.
pub const EMPTY_TREE_HASH: TreeHash = TreeHash([0; 32]);

impl Deref for TreeHash {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 32]> for TreeHash {
    fn from(value: [u8; 32]) -> Self {
        TreeHash(value)
    }
}

/// A set of auxiliary hashes for a tree.
pub type TreeHashes = SerdeVec<TreeHash, MAX_AUX_HASHES>;

/// When PinWeaver needs to store a high-entropy secret that is larger than
/// 32 bytes, the leaf's secret is an AES key used with these parameters.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct LargeSecretInfo {
    /// The IV for the ciphertext/key. Must not be reused.
    pub iv: LargeSecretIv,

    /// The GCM authentication tag used to verify that the low-entropy secret
    /// is associated with this ciphertext.
    pub auth_tag: LargeSecretAuthTag,

    /// The encrypted high-entropy secret, decrypted with the key stored on the PinWeaver leaf.
    pub secret_ciphertext: SerdeVec<u8, MAX_LARGE_SECRET_SIZE>,
}

/// An AES-256 Initialization Vector.
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize), serde(transparent))]
pub struct LargeSecretIv(
    #[cfg_attr(feature = "serde", serde(with = "util::hex_serde"))] pub [u8; 12],
);

/// The GCM [authentication tag] ensuring integrity of large-secret data.
///
/// [authentication tag]: https://en.wikipedia.org/wiki/Authenticated_encryption
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize), serde(transparent))]
pub struct LargeSecretAuthTag(pub U32);

serde_fields! {
    LargeSecretInfo { iv, auth_tag, secret_ciphertext },
}
serde_zerocopy!(LargeSecretAuthTag, LargeSecretIv, LeafId, LeafSet, Path, TreeHash, TreeParams);

impl From<LeafId> for i64 {
    fn from(id: LeafId) -> i64 {
        ((id.leaf_set.0.get() as i64) << 32) | (id.inner_id.get() as i64)
    }
}

impl From<i64> for LeafId {
    fn from(id: i64) -> LeafId {
        let inner_id = U32::new((id & 0x00000000ffffffff) as u32);
        let leaf_set = LeafSet(U32::new((u64::from_ne_bytes(id.to_ne_bytes()) >> 32) as u32));
        LeafId { leaf_set, inner_id }
    }
}

impl From<Path> for u64 {
    fn from(path: Path) -> u64 {
        zerocopy::transmute!(path)
    }
}

impl From<u64> for Path {
    fn from(path: u64) -> Path {
        zerocopy::transmute!(path)
    }
}
