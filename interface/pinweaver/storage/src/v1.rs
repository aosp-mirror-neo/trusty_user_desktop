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

//! Version 1 of the PinWeaver storage daemon interface.

use crate::util::{serde_fields, serde_zerocopy, SerdeVec};
use std::fmt::Debug;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub mod request;
pub mod response;

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

/// The interface to communicate with the storage daemon.
pub trait StorageInterface: 'static + Sync + Send {
    /// The error while executing a storage request.
    type Error: Debug;

    /// Execute a storage request.
    fn request(&self, request: &StorageRequest) -> Result<StorageResponse, Self::Error>;
}

pub use request::StorageRequest;
pub use response::StorageResponse;

/// Unaligned `u32` - used for `AsBytes` structs to prevent padding.
pub type U32 = zerocopy::byteorder::U32<zerocopy::byteorder::LE>;

/// A leaf identifier, distinct from a [`Path`] and specific to the Android PinWeaver API.
///
/// Both the leaf set and inner ID are client-chosen.
///
/// This has a 1:1 mapping with some [`Path`] on this device,
/// except when a leaf with some ID is currently being replaced.
#[derive(AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct LeafId {
    leaf_set: U32,
    inner_id: U32,
}

/// A PinWeaver leaf path, indicating where in the hash tree a leaf is located.
#[derive(AsBytes, Clone, Copy, FromBytes, FromZeroes)]
#[repr(transparent)]
pub struct Path([u8; 8]);

/// The encrypted contents of a PinWeaver leaf on-disk.
pub type LeafContents = SerdeVec<u8, LEAF_SIZE>;

/// Parameters for a PinWeaver hash tree.
#[derive(AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct TreeParams {
    /// The height of the new tree.
    pub height: u8,

    /// The number of bits in the path used per tree level.
    /// This is log2(fan-out factor).
    pub bits_per_level: u8,
}

#[derive(AsBytes, FromBytes, FromZeroes)]
#[repr(transparent)]
/// A SHA-256 digest.
pub struct TreeHash([u8; 32]);

/// A set of auxiliary hashes for a tree.
pub type TreeHashes = SerdeVec<TreeHash, MAX_AUX_HASHES>;

/// When PinWeaver needs to store a high-entropy secret that is larger than
/// 32 bytes, the leaf's secret is an AES key used with these parameters.
#[repr(C)]
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
#[derive(AsBytes, FromBytes, FromZeroes)]
#[repr(transparent)]
pub struct LargeSecretIv([u8; 12]);

/// The GCM [authentication tag] ensuring integrity of large-secret data.
///
/// [authentication tag]: https://en.wikipedia.org/wiki/Authenticated_encryption
#[derive(AsBytes, FromBytes, FromZeroes)]
#[repr(transparent)]
pub struct LargeSecretAuthTag([u8; 4]);

serde_fields! {
    LargeSecretInfo { iv, auth_tag, secret_ciphertext },
}
serde_zerocopy!(TreeHash, LeafId, Path, LargeSecretAuthTag, LargeSecretIv);
